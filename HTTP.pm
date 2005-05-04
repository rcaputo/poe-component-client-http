package POE::Component::Client::HTTP;

# {{{ INIT

use strict;
#use bytes; # for utf8 compatibility

sub DEBUG         () { 1 }
sub DEBUG_DATA    () { 0 }

# keep-alive support enabled?
sub K () { 1 }

use vars qw($VERSION);
$VERSION = '0.65';

use Carp qw(croak);
use POSIX;
use Symbol qw(gensym);
use HTTP::Response;
use HTTP::Status qw(status_message);
use URI;
use HTML::HeadParser;

use POE::Component::Client::HTTP::RequestFactory;
use POE::Component::Client::HTTP::Request qw(:states :fields);

# Allow more finely grained timeouts if Time::HiRes is available.
BEGIN {
  local $SIG{'__DIE__'} = 'DEFAULT';
  eval {
    require Time::HiRes;
    Time::HiRes->import("time");
  };
}

use POE qw(
  Wheel::SocketFactory Wheel::ReadWrite
  Driver::SysRW Filter::Stream
  Filter::HTTPHead Filter::HTTPChunk
  Component::Client::DNS
);

# {{{ Bring in HTTPS support.

BEGIN {
  my $has_ssl = 0;
  eval { require POE::Component::Client::HTTP::SSL };
  if (
    defined $Net::SSLeay::VERSION and
    defined $Net::SSLeay::Handle::VERSION and
    $Net::SSLeay::VERSION >= 1.17 and
    $Net::SSLeay::Handle::VERSION >= 0.61
  ) {
    $has_ssl = 1;
  }
  eval "sub HAS_SSL () { $has_ssl }";
}

# }}} Bring in HTTPS support.

# }}} INIT

#------------------------------------------------------------------------------
# Spawn a new PoCo::Client::HTTP session.  This basically is a
# constructor, but it isn't named "new" because it doesn't create a
# usable object.  Instead, it spawns the object off as a separate
# session.
# {{{ spawn

sub spawn {
  my $type = shift;

  croak "$type requires an even number of parameters" if @_ % 2;

  my %params = @_;

  my $alias = delete $params{Alias};
  $alias = 'weeble' unless defined $alias and length $alias;

  my $timeout = delete $params{Timeout};
  $timeout = 180 unless defined $timeout and $timeout >= 0;

  POE::Component::Client::DNS->spawn(
      Alias   => "poco_${alias}_resolver",
      Timeout => $timeout,
    );

  my $request_factory = POE::Component::Client::HTTP::RequestFactory->new (\%params);

  croak(
    "$type doesn't know these parameters: ",
    join(', ', sort keys %params)
  ) if scalar keys %params;

  POE::Session->create(
    inline_states => {
      _start  => \&poco_weeble_start,
      _stop   => \&poco_weeble_stop,

      # Public interface.
      request                => \&poco_weeble_request,
      pending_requests_count => \&poco_weeble_pending_requests_count,

      # Net::DNS interface.
      got_dns_response  => \&poco_weeble_dns_answer,
      do_connect        => \&poco_weeble_do_connect,

      # SocketFactory interface.
      got_connect_done  => \&poco_weeble_connect_ok,
      got_connect_error => \&poco_weeble_connect_error,

      # ReadWrite interface.
      got_socket_input  => \&poco_weeble_io_read,
      got_socket_flush  => \&poco_weeble_io_flushed,
      got_socket_error  => \&poco_weeble_io_error,

      # I/O timeout.
      got_timeout       => \&poco_weeble_timeout,
    },
    heap => {
      alias         => $alias,
      timeout       => $timeout,
      factory	    => $request_factory,
    },
  );

  undef;
}

# }}} spawn
# ------------------------------------------------------------------------------
# {{{ poco_weeble_start

sub poco_weeble_start {
  my ($kernel, $heap) = @_[KERNEL, HEAP];

  $kernel->alias_set($heap->{alias});
}

# }}} poco_weeble_start
#------------------------------------------------------------------------------
# {{{ poco_weeble_stop

sub poco_weeble_stop {
  my $heap = shift;
  delete $heap->{request};
  DEBUG and warn "$heap->{alias} stopped.\n";
}

# }}} poco_weeble_stop
# {{{ poco_weeble_pending_requests_count

sub poco_weeble_pending_requests_count {
  my ($heap) = $_[HEAP];
  my $r = $heap->{request} || {};
  return keys %$r;
}

# }}} poco_weeble_pending_requests_count
#------------------------------------------------------------------------------
# {{{ poco_weeble_request

sub poco_weeble_request {
  my (
    $kernel, $heap, $sender,
    $response_event, $http_request, $tag, $progress_event
  ) = @_[KERNEL, HEAP, SENDER, ARG0, ARG1, ARG2, ARG3];


  my $request = $heap->{factory}->create_request (
      $http_request, $response_event, $tag, $progress_event, $sender
    );

  # Bail out if no SSL and we need it.
  if ($http_request->uri->scheme() eq 'https') {
      unless (HAS_SSL) {
          _post_error($request, "Net::SSLeay 1.17 or newer is required for https");
          return;
      }
  }

  my $host = $http_request->uri->host;
  my $port = $http_request->uri->port;

  # -><- Should probably check for IPv6 addresses here, too.
  if ($host !~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) {

      if (exists $heap->{resolve}->{$host}) {
          DEBUG and warn "DNS: $host is piggybacking on a pending lookup.\n";
          push @{$heap->{resolve}->{$host}}, $request->ID;
      } elsif (exists $heap->{address_to_wheel}->{"$host:$port"}) {
          DEBUG and warn "DNS: reusing existing connection for $host.\n";
          $kernel->yield( do_connect => $request->ID, $host );
      } else {
          DEBUG and warn "DNS: $host is being looked up in the background.\n";
          $heap->{resolve}->{$host} = [ $request->ID ];
          my $my_alias = $heap->{alias};
          $kernel->post(
            "poco_${my_alias}_resolver" =>
            resolve => got_dns_response => $host => "A", "IN"
          );
      }
  } else {
      DEBUG and warn "DNS: $host may block while it's looked up.\n";
      $kernel->yield( do_connect => $request->ID, $host );
  }

  $heap->{request}->{$request->ID} = $request;
}

# }}} poco_weeble_request
#------------------------------------------------------------------------------
# Non-blocking DNS lookup stage.
# {{{ poco_weeble_dns_answer

sub poco_weeble_dns_answer {
  my ($kernel, $heap) = @_[KERNEL, HEAP];
  my $request_address = $_[ARG0]->[0];
  my $response_object = $_[ARG1]->[0];
  my $response_error  = $_[ARG1]->[1];

  my $requests = delete $heap->{resolve}->{$request_address};

  DEBUG and warn "DNS: request address = $request_address";

  # No requests are on record for this lookup.
  die "!!!: Unexpectedly undefined requests" unless defined $requests;

  # No response.
  unless (defined $response_object) {
    foreach my $request_id (@$requests) {
      DEBUG and warn "I/O: removing request $request_id";
      my $request = delete $heap->{request}->{$request_id};
      _post_error($request, $response_error);
    }
    return;
  }

  # A response!
  foreach my $answer ($response_object->answer()) {
    next unless $answer->type eq "A";

    DEBUG and
      warn "DNS: $request_address resolves to ", $answer->rdatastr(), "\n";

    foreach my $request_id (@$requests) {
      $kernel->yield( do_connect => $request_id, $answer->rdatastr );
    }

    # Return after the first good answer.
    return;
  }

  # Didn't return here.  No address record for the host?
  foreach my $request_id (@$requests) {
    DEBUG and warn "I/O: removing request $request_id";
    my $request = delete $heap->{request}->{$request_id};
    _post_error($request, "Host has no address.");
  }
}

# }}} poco_weeble_dns_answer
#------------------------------------------------------------------------------
# {{{ poco_weeble_do_connect

sub poco_weeble_do_connect {
    my ($kernel, $heap, $request_id, $address) = @_[KERNEL, HEAP, ARG0, ARG1];

    my $request = $heap->{request}->{$request_id};

    my ($socket, $socket_factory, $keep_alive);

    # Check to see if this is a keepalive reuse

    my $hostport = "$request->[REQ_HOST]:$request->[REQ_PORT]";
    if (K
        and  exists $heap->{address_to_wheel}->{$hostport}
        and defined $heap->{address_to_wheel}->{$hostport}
       ) {

        DEBUG and warn "CON: Reusing socket (request ID = $request_id)\n";
	#FIXME: this needs to be fixed, since you can't assign things to
	#       a normal sub. needs a test that comes here every time
        $socket_factory = $request->wheel( $heap->{address_to_wheel}->{$hostport});
    	$request->wheel->set_input_filter (POE::Filter::HTTPHead->new);
        $keep_alive++;

    } else {

        K and DEBUG and warn "CON: Not reusing socket (request ID = $request_id)\n";

        # Create a socket factory.
        $socket_factory =
          $request->wheel (
            POE::Wheel::SocketFactory->new(
              RemoteAddress => $address,
              RemotePort    => $request->[REQ_PORT],
              SuccessEvent  => 'got_connect_done',
              FailureEvent  => 'got_connect_error',
            ));

    }

    $request->create_timer ($heap->{timeout});

    # Cross-reference the wheel and timer IDs back to the request.
    $heap->{timer_to_request}->{$request->[REQ_TIMER]} = $request_id;
    $heap->{wheel_to_request}->{$socket_factory->ID()} = $request_id;

    DEBUG and warn(
      "CON: wheel ", $socket_factory->ID,
      " (request $request_id)",
      " is connecting to $request->[REQ_HOST] : $request->[REQ_PORT] ...\n"
    );

    # We don't have to connect_ok() if we're using a cached wheel.  Just
    # send the request.
    if ($keep_alive) {
        #_put_request($request);
	$request->send_to_wheel;
    }

}

# }}} poco_weeble_do_connect
#------------------------------------------------------------------------------
# {{{ poco_weeble_connect_ok

sub poco_weeble_connect_ok {
    my ($heap, $socket, $wheel_id) = @_[HEAP, ARG0, ARG3];

    # Remove the old wheel ID from the look-up table.
    my $request_id = delete $heap->{wheel_to_request}->{$wheel_id};
    if (not defined $request_id) {
      DEBUG and warn "!!!: Unexpectedly undefined request ID";
      return;
    }

    DEBUG and warn "CON: wheel $wheel_id (request $request_id) connected ok...\n";

    my $request = $heap->{request}->{$request_id};

# {{{ Switch the handle to SSL if we're doing that.

    if ($request->[REQ_REQUEST]->uri->scheme() eq 'https') {
        DEBUG and warn "CON: wheel $wheel_id switching to SSL...\n";

        # Net::SSLeay needs blocking for setup.
        #
        # ActiveState Perl 5.8.0 dislikes the Win32-specific code to make
        # a socket blocking, so we use IO::Handle's blocking(1) method.
        # Perl 5.005_03 doesn't like blocking(), so we only use it in
        # 5.8.0 and beyond.
        #
        # TODO - This code should probably become a POE::Kernel method,
        # seeing as it's rather baroque and potentially useful in a number
        # of places.
        my $old_socket = $socket;
        if ($] >= 5.008) {
            $old_socket->blocking(1);
        } else {
            # Make the handle blocking, the POSIX way.
            unless ($^O eq 'MSWin32') {
                my $flags = fcntl($old_socket, F_GETFL, 0)
                  or die "!!!: fcntl($old_socket, F_GETFL, etc.) fails: $!";
                until (fcntl($old_socket, F_SETFL, $flags & ~O_NONBLOCK)) {
                    die "!!!: fcntl($old_socket, FSETFL, etc) fails: $!"
                      unless $! == EAGAIN or $! == EWOULDBLOCK;
                }
            }
            # Do it the Win32 way.
            else {
                my $set_it = "0";

                # 126 is FIONBIO (some docs say 0x7F << 16)
                ioctl( $old_socket,
                       0x80000000 | (4 << 16) | (ord('f') << 8) | 126,
                       $set_it
                     )
                  or die "!!!: ioctl($old_socket, FIONBIO, $set_it) fails: $!";
            }
        }

        $socket = gensym();
        tie(
          *$socket,
          "POE::Component::Client::HTTP::SSL",
          $old_socket
        ) or die "!!!: error tying socket to SSL wrapper: $!";

        DEBUG and warn "CON: wheel $wheel_id switched to SSL...\n";
    }

# }}} Switch the handle to SSL if we're doing that.

    my $block_size = $heap->{factory}->block_size;

    # Make a ReadWrite wheel to interact on the socket.
    my $new_wheel = POE::Wheel::ReadWrite->new(
      Handle       => $socket,
      Driver       => POE::Driver::SysRW->new(BlockSize => $block_size),
      #Filter       => POE::Filter::Stream->new(),
      InputFilter  => POE::Filter::HTTPHead->new(),
      OutputFilter => POE::Filter::Stream->new(),
      InputEvent   => 'got_socket_input',
      FlushedEvent => 'got_socket_flush',
      ErrorEvent   => 'got_socket_error',
    );

    DEBUG and warn "CON: wheel $wheel_id became wheel ", $new_wheel->ID, "\n";

    # Add the new wheel ID to the lookup table.

    $heap->{wheel_to_request}->{ $new_wheel->ID() } = $request_id;

    $request->wheel ($new_wheel);

    K and DEBUG and warn "CON: stashing output wheel " . $new_wheel->ID . "\n";
    my $hostport = $request->[REQ_HOST] . ':' . $request->[REQ_PORT];
    K and $heap->{address_to_wheel}->{$hostport} = $new_wheel;
    K and $heap->{wheel_to_address}->{$new_wheel->ID} = $hostport;

    # WHEEL INITIALIZED

    # warn "DON'T REQUIRE ME TO CONNECT BEFORE I START SENDING, PLEASE!";
    # warn "Assume each request is brand new, is there 'init_request' behavior here that should be better grouped?!";

    $request->send_to_wheel;

}

# }}} poco_weeble_connect_ok
#------------------------------------------------------------------------------
# {{{ poco_weeble_connect_error

sub poco_weeble_connect_error {
    my ($kernel, $heap, $operation, $errnum, $errstr, $wheel_id) =
      @_[KERNEL, HEAP, ARG0..ARG3];

    warn "CON: Error with wheel $wheel_id";
    # Drop the wheel and its cross-references.
    my $request_id = delete $heap->{wheel_to_request}->{$wheel_id};
    #die "!!!: expected a request ID, but there is none" unless defined $request_id;

    DEBUG and
      warn "CON: wheel $wheel_id (request $request_id) encountered $operation error $errnum: $errstr\n";

    warn "I/O: removing request $request_id";
    my $request = delete $heap->{request}->{$request_id};

    _remove_timeout($kernel, $heap, $request);

    # Post an error response back to the requesting session.
    _post_error($request, "$operation error $errnum: $errstr");
}

# }}} poco_weeble_connect_error
#------------------------------------------------------------------------------
# {{{ poco_weeble_timeout

sub poco_weeble_timeout {
  my ($kernel, $heap, $request_id) = @_[KERNEL, HEAP, ARG0];

  DEBUG and warn "TKO: request $request_id timed out\n";

  # Discard the request.  Keep a copy for a few bits of cleanup.
  DEBUG and warn "I/O: removing request $request_id";
  my $request = delete $heap->{request}->{$request_id};

  unless (defined $request) {
    die(
      "TKO: unexpectedly undefined request for id $request_id\n",
      "TKO: known request IDs: ", join(", ", keys %{$heap->{request}}), "\n",
      "...",
    );
  }

  DEBUG and warn "TKO: request $request_id has timer $request->[REQ_TIMER]\n";

  # There's a wheel attached to the request.  Shut it down.
  if (defined $request->wheel) {
    my $wheel_id = $request->wheel->ID();
    DEBUG and warn "TKO: request $request_id is wheel $wheel_id\n";
    delete $heap->{wheel_to_request}->{$wheel_id};

    # DEBUG and warn $request;

    K and my $hostport = delete $heap->{wheel_to_address}->{$wheel_id};
    K and delete $heap->{address_to_wheel}->{$hostport};

  }

  # No need to remove the alarm here because it's already gone.
  delete $heap->{timer_to_request}->{ $request->[REQ_TIMER] };

  DEBUG and die  "TKO: request $request_id is unexpectedly zero" unless $request->[REQ_STATE];
  DEBUG and warn "TKO: request_state = " . sprintf("%#04x\n", $request->[REQ_STATE]);

  if ($request->[REQ_STATE] & (RS_IN_CONTENT | RS_DONE) and not $request->[REQ_STATE] & RS_POSTED) {

    #warn "request_id is $request_id, while request's id is $request->[REQ_ID]";
    _finish_request($heap, $request_id, $request);
    return;
  } elsif ($request->[REQ_STATE] & RS_POSTED) {
    #K and DEBUG and warn "I/O: Disconnect, keepalive timeout or HTTP/1.0.\n";
    $request->[REQ_POSTBACK]->(HTTP::Response->new(408, "Request timed out")) if $request->[REQ_STATE];
    return;
  }
  # Post an error response back to the requesting session.
}

# }}} poco_weeble_timeout
#------------------------------------------------------------------------------
# {{{ poco_weeble_io_flushed

sub poco_weeble_io_flushed {
  my ($heap, $wheel_id) = @_[HEAP, ARG0];

  # We sent the request.  Now we're looking for a response.  It may be
  # bad to assume we won't get a response until a request has flushed.
  my $request_id = $heap->{wheel_to_request}->{$wheel_id};
  if (not defined $request_id) {
    DEBUG and warn "!!!: unexpectedly undefined request ID";
    return;
  }

  DEBUG and warn "I/O: wheel $wheel_id (request $request_id) flushed its request...\n";

  my $request = $heap->{request}->{$request_id};
  $request->[REQ_STATE] ^= RS_SENDING;
  $request->[REQ_STATE] = RS_IN_STATUS;
  # XXX - Removed a second time.  The first time was in version 0.53,
  # because the EOF generated by shutdown_output() causes some servers
  # to disconnect rather than send their responses.
  # $request->wheel->shutdown_output();
}

# }}} poco_weeble_io_flushed
#------------------------------------------------------------------------------
# {{{ poco_weeble_io_error

sub poco_weeble_io_error {
    my ($kernel, $heap, $operation, $errnum, $errstr, $wheel_id) =
      @_[KERNEL, HEAP, ARG0..ARG3];

    DEBUG and
      warn "I/O: wheel $wheel_id encountered $operation error $errnum: $errstr\n";

    # Drop the wheel.
    my $request_id = delete $heap->{wheel_to_request}->{$wheel_id};
    K or die "!!!: unexpectedly undefined request ID" unless defined $request_id;

    # Drop the wheel's cached connection, too.
    K and my $hostport = delete $heap->{wheel_to_address}->{$wheel_id};
    K and delete $heap->{address_to_wheel}->{$hostport};

    if ($request_id ) {

        DEBUG and warn "I/O: removing request $request_id";
        my $request = delete $heap->{request}->{$request_id};
        _remove_timeout($kernel, $heap, $request);

        # If there was a non-zero error, then something bad happened.  Post
        # an error response back.
        if ($errnum) {
            $request->[REQ_POSTBACK]->(
              HTTP::Response->new( 400, "$operation error $errnum: $errstr" )
            );
            return;
        }

        # Otherwise the remote end simply closed.  If we've got a
        # pending response, then post it back to the client.
	DEBUG and warn "STATE is ", $request->[REQ_STATE];
        if ($request->[REQ_STATE] & (RS_IN_CONTENT | RS_DONE) and not $request->[REQ_STATE] & RS_POSTED) {

            _finish_request($heap, $request_id, $request);

            return;
        } elsif ($request->[REQ_STATE] & RS_POSTED) {
            K and DEBUG and warn "I/O: Disconnect, keepalive timeout or HTTP/1.0.\n";
            return;
        }

        # We haven't built a proper response.  Send back an error.
        $request->[REQ_POSTBACK]->(
          HTTP::Response->new( 400, "incomplete response $request_id" )
        );
    }
}

# }}} poco_weeble_io_error
#------------------------------------------------------------------------------
# Read a chunk of response.  This code is directly adapted from Artur
# Bergman's nifty POE::Filter::HTTPD, which does pretty much the same
# in the other direction.
# {{{ poco_weeble_io_read

sub poco_weeble_io_read {
  my ($kernel, $heap, $input, $wheel_id) = @_[KERNEL, HEAP, ARG0, ARG1];
  my $request_id = $heap->{wheel_to_request}->{$wheel_id};

  DEBUG and warn "I/O: wheel $wheel_id got input...\n";
  DEBUG_DATA and warn((ref($input) ? $input->as_string : _hexdump($input)), "\n");

  return unless defined $request_id;
  die unless defined $request_id;
  my $request = $heap->{request}->{$request_id};
  return unless defined $request;
  DEBUG and warn "REQUEST is $request";

  # Reset the timeout if we get data.
  $kernel->delay_adjust($request->[REQ_TIMER], $heap->{timeout});

# {{{ HEAD

  # The very first line ought to be status.  If it's not, then it's
  # part of the content.
  if ($request->[REQ_STATE] & RS_IN_STATUS) {
    my $filter = $request->wheel->get_input_filter;
    #warn "FILTER is $filter";
    if (defined $input) {
      $input->request ($request->[REQ_REQUEST]);
      #warn "INPUT for ", $request->[REQ_REQUEST]->uri, " is \n",$input->as_string;
    } else {
      #warn "NO INPUT\n";
    }
    # FIXME: LordVorp gets here without $input being a HTTP::Response
    $request->[REQ_RESPONSE] = $input;
    if ($request->[REQ_REQUEST]->method eq 'HEAD'
     || $input->code =~ /^(?:1|[23]04)/) {
      $request->[REQ_STATE] = RS_DONE;
    } else {
      $request->[REQ_STATE] = RS_IN_CONTENT;
      my $te = $input->header('Transfer-Encoding');
      my @te = split(/\s*,\s*/, lc($te));
      $te = pop(@te);
      DEBUG and warn "I/O: transfer encoding $te";
      if (my $newrequest = $request->check_redirect) {
	$kernel->yield (request => $request,
	  $newrequest, "_redir_".$request->ID, $request->[REQ_PROG_POSTBACK]);
      }

      # do this last, because it triggers a read
      if ($te eq 'chunked') {
	$request->wheel->set_input_filter (POE::Filter::HTTPChunk->new (Response => $input));
      } else {
	$request->wheel->set_input_filter (POE::Filter::Stream->new);
      }
    }
    return;
  }

# }}} HEAD

  # Aggregate the new input.
  #warn "got more input '$input'";

  if ($request->[REQ_STATE] & RS_IN_CONTENT) {
    if (ref($input)) {
      $request->[REQ_STATE] = RS_DONE;
    } else {
      $request->[REQ_BUFFER] .= $input;
    }
  }

# {{{ content

  # We're in a content state.  This isn't an else clause because we
  # may go from header to content in the same read.
  if ($request->[REQ_STATE] & RS_IN_CONTENT) {


    # First pass the new chunk through our HeadParser, if we have one.
    # This also destroys the HeadParser if its purpose is done.
    if ($request->[REQ_HEAD_PARSER]) {
      $request->[REQ_HEAD_PARSER]->parse($request->[REQ_BUFFER]) or
	$request->[REQ_HEAD_PARSER] = undef;
    }

    # Count how many octets we've received.  -><- This may fail on
    # perl 5.8 if the input has been identified as Unicode.  Then
    # again, the C<use bytes> in Driver::SysRW may have untainted the
    # data... or it may have just changed the semantics of length()
    # therein.  If it's done the former, then we're safe.  Otherwise
    # we also need to C<use bytes>.
    my $this_chunk_length = length($request->[REQ_BUFFER]);
    $request->[REQ_OCTETS_GOT] += $this_chunk_length;


    $heap->{factory}->check_size_constraint ($request);
    # If we are streaming, send the chunk back to the client session.
    # Otherwise add the new octets to the response's content.  -><-
    # This should only add up to content-length octets total!
    if ($heap->{factory}->is_streaming) {
      $request->[REQ_POSTBACK]->(
	$request->[REQ_RESPONSE], $request->[REQ_BUFFER]
      );
    } else {
      $request->[REQ_RESPONSE]->add_content($request->[REQ_BUFFER]);
    }

    DEBUG and do {
      warn "I/O: wheel $wheel_id got $this_chunk_length octets of content...\n";
      warn(
	  "I/O: wheel $wheel_id has $request->[REQ_OCTETS_GOT]",
	  ( $request->[REQ_RESPONSE]->content_length()
	    ? ( " out of " . $request->[REQ_RESPONSE]->content_length() )
	    : ""
	  ),
	  " octets\n"
	  );
    };

    # Stop reading when we have enough content.  -><- Should never be
    # greater than our content length.
    if ( $request->[REQ_RESPONSE]->content_length() ) {

      # TODO - Remove this?  Or pass the information to the user?
      #my $progress = int( ($request->[REQ_OCTETS_GOT] * 100) /
      #                    $request->[REQ_RESPONSE]->content_length()
      #                  );

      $request->[REQ_PROG_POSTBACK]->(
	$request->[REQ_OCTETS_GOT],
	$request->[REQ_RESPONSE]->content_length(),
	$request->[REQ_BUFFER],
      ) if $request->[REQ_PROG_POSTBACK];

      if (
	$request->[REQ_OCTETS_GOT] >= $request->[REQ_RESPONSE]->content_length()
      ) {
	DEBUG and
	  warn "I/O: wheel $wheel_id has a full response... moving to done.\n";

	$request->[REQ_STATE] = RS_DONE;

	# KeepAlive -- now we support KeepAlives, and content
	# is delivered independantly of connection state.

	# Original note:
	# -><- This assumes the server will now disconnect.  That will
	# give us an error 0 (socket's closed), and we will post the
	# response.

      }
    }
  }

# }}} content

  $request->[REQ_BUFFER] = '';

# {{{ not done yet?

  unless ($request->[REQ_STATE] & RS_DONE) {

    if (
	defined($heap->{max_size}) and
	$request->[REQ_OCTETS_GOT] >= $heap->{max_size}
       ) {
      DEBUG and
	warn "I/O: wheel $wheel_id got enough data... moving to done.\n";

      if (
	  defined($request->[REQ_RESPONSE]) and
	  defined($request->[REQ_RESPONSE]->code())
	 ) {
	$request->[REQ_RESPONSE]->header(
	    'X-Content-Range',
	    'bytes 0-' . $request->[REQ_OCTETS_GOT] .
	    ( $request->[REQ_RESPONSE]->content_length()
	      ? ('/' . $request->[REQ_RESPONSE]->content_length())
	      : ''
	    )
	    );
      } else {
	$request->[REQ_RESPONSE] =
	  HTTP::Response->new( 400, "Response too large (and no headers)" );
      }

      $request->[REQ_STATE] = RS_DONE;

# warn "DON'T REQUIRE ME TO DISCONNECT BEFORE I DISSEMINATE MY CONTENTS, PLEASE!";

      my ($request_id, $request);

      if (K) {
# this doesn't seem to affect anything ??
	$request_id = $heap->{wheel_to_request}->{$wheel_id};
	$request    = $heap->{request}->{$request_id};
      } else {
# Hang up on purpose.
	$request_id = delete $heap->{wheel_to_request}->{$wheel_id};
	DEBUG and warn "I/O: removing request $request_id";
	$request    = delete $heap->{request}->{$request_id};
      }

      _remove_timeout($kernel, $heap, $request);

      _finish_request($heap, $request_id, $request);
    }
  }

# }}} not done yet?

# {{{ deliver reponse if complete

# POST response without disconnecting
  if (K and $request->[REQ_STATE] & RS_DONE and not $request->[REQ_STATE] & RS_POSTED) {
    DEBUG and warn(
	"I/O: Calling finish_request() from 'post_finished_requests' of io_read\n",
	"I/O: $request->[REQ_ID] or $request_id\n",
	"I/O: postback = $request->[REQ_POSTBACK]\n",
	);
    _finish_request($heap, $request_id, $request);
    _remove_timeout($kernel, $heap, $request);
  }

# }}} deliver reponse if complete

}

# }}} poco_weeble_io_read


#------------------------------------------------------------------------------
# Generate a hex dump of some input. This is not a POE function.
# {{{ _hexdump

sub _hexdump {
  my $data = shift;

  my $dump;
  my $offset = 0;
  while (length $data) {
    my $line = substr($data, 0, 16);
    substr($data, 0, 16) = '';

    my $hexdump  = unpack 'H*', $line;
    $hexdump =~ s/(..)/$1 /g;

    $line =~ tr[ -~][.]c;
    $dump .= sprintf( "%04x %-47.47s - %s\n", $offset, $hexdump, $line );
    $offset += 16;
  }

  return $dump;
}

# }}} _hexdump
#------------------------------------------------------------------------------
# Post an error message.  This is not a POE function.
# {{{ _post_error

sub _post_error {
  my ($request, $message) = @_;

  my $nl = "\n";

  my $host = $request->[REQ_HOST];
  my $port = $request->[REQ_PORT];

  my $response = HTTP::Response->new(500);
  $response->content(
    "<HTML>$nl" .
    "<HEAD><TITLE>An Error Occurred</TITLE></HEAD>$nl" .
    "<BODY>$nl" .
    "<H1>An Error Occurred</H1>$nl" .
    "500 Cannot connect to $host:$port ($message)$nl" .
    "</BODY>$nl" .
    "</HTML>$nl"
  );

  $request->[REQ_POSTBACK]->($response);
}

# }}} _post_error
#------------------------------------------------------------------------------
# Complete a request. This was moved out of poco_weeble_io_error(). This is
# not a POE function.
# {{{ _finish_request

sub _finish_request {
  my ($heap, $request_id, $request) = @_;

  if (DEBUG) {
    my ($pkg, $file, $line) = caller();
    DEBUG and warn "XXX: calling _finish_request(request id = $request_id) at $file line $line\n";
  }

  # If we have a cookie jar, have it frob our headers.  LWP rocks!
  $heap->{factory}->frob_cookies ($request);

  # If we're streaming, the response is HTTP::Response without
  # content and undef to signal the end of the stream.  Otherwise
  # it's the entire HTTP::Response object we've carefully built.
  if ($heap->{factory}->is_streaming) {
    $request->[REQ_POSTBACK]->($request->[REQ_RESPONSE], undef);
  } else {
    $request->[REQ_POSTBACK]->($request->[REQ_RESPONSE]);
  }

  # KeepAlive: added the RS_POSTED flag
  $request->[REQ_STATE] = RS_DONE | RS_POSTED;

  my $wheel = $request->wheel;
  DEBUG and warn "Wheel from request is ", $wheel->ID;
  # clean up the request
  my $address = "$request->[REQ_HOST]:$request->[REQ_PORT]";
  if ($heap->{address_to_wheel}->{$address}) {
    my $wheel_id = $heap->{address_to_wheel}->{$address}->ID();
    DEBUG and warn "wheel for $address is $wheel_id";
    if ($wheel->ID == $wheel_id) {
      my $other_request_id = $heap->{wheel_to_request}->{$wheel_id};
      DEBUG and warn "other request is $other_request_id";
      do {
	DEBUG and warn "deleting address_to_wheel";
	delete $heap->{address_to_wheel}
      }
	if (	not defined ($other_request_id)
	    or  $request_id == $other_request_id
	);
    }
  }

  DEBUG and warn "I/O: removing request $request_id";
  my $request = delete $heap->{request}->{$request_id};
}

# }}} _finish_request

#------------------------------------------------------------------------------
# Cancel a request timeout. This was all over the place and is now a function.
# This is not a POE function.
# {{{ _remove_timeout

sub _remove_timeout {
    my ($kernel, $heap, $request) = @_;
    # Stop the timeout timer for this wheel, too.
    my $alarm_id = $request->[REQ_TIMER];
    if (delete $heap->{timer_to_request}->{$alarm_id}) {
        $kernel->alarm_remove( $alarm_id );
    }
}

# }}} _remove_timeout

1;

__END__

# {{{ POD

=head1 NAME

POE::Component::Client::HTTP - a HTTP user-agent component

=head1 SYNOPSIS

  use POE qw(Component::Client::HTTP);

  POE::Component::Client::HTTP->spawn(
    Agent     => 'SpiffCrawler/0.90',   # defaults to something long
    Alias     => 'ua',                  # defaults to 'weeble'
    From      => 'spiffster@perl.org',  # defaults to undef (no header)
    Protocol  => 'HTTP/0.9',            # defaults to 'HTTP/1.0'
    Timeout   => 60,                    # defaults to 180 seconds
    MaxSize   => 16384,                 # defaults to entire response
    Streaming => 4096,                  # defaults to 0 (off)
    FollowRedirects => 2                # defaults to 0 (off)
    Proxy     => "http://localhost:80", # defaults to HTTP_PROXY env. variable
    NoProxy   => [ "localhost", "127.0.0.1" ], # defs to NO_PROXY env. variable
  );

  $kernel->post(
    'ua',        # posts to the 'ua' alias
    'request',   # posts to ua's 'request' state
    'response',  # which of our states will receive the response
    $request,    # an HTTP::Request object
  );

  # This is the sub which is called when the session receives a
  # 'response' event.
  sub response_handler {
    my ($request_packet, $response_packet) = @_[ARG0, ARG1];

    # HTTP::Request
    my $request_object  = $request_packet->[0];

    # HTTP::Response
    my $response_object = $response_packet->[0];

    my $stream_chunk;
    if (! defined($response_object->content)) {
      $stream_chunk = $response_packet->[1];
    }

    print(
      "*" x 78, "\n",
      "*** my request:\n",
      "-" x 78, "\n",
      $request_object->as_string(),
      "*" x 78, "\n",
      "*** their response:\n",
      "-" x 78, "\n",
      $response_object->as_string(),
    );

    if (defined $stream_chunk) {
      print "-" x 40, "\n", $stream_chunk, "\n";
    }

    print "*" x 78, "\n";
  }

=head1 DESCRIPTION

POE::Component::Client::HTTP is an HTTP user-agent for POE.  It lets
other sessions run while HTTP transactions are being processed, and it
lets several HTTP transactions be processed in parallel.

If POE::Component::Client::DNS is also installed, Client::HTTP will
use it to resolve hosts without blocking.  Otherwise it will use
gethostbyname(), which may have performance problems.

HTTP client components are not proper objects.  Instead of being
created, as most objects are, they are "spawned" as separate sessions.
To avoid confusion (and hopefully not cause other confusion), they
must be spawned with a C<spawn> method, not created anew with a C<new>
one.

PoCo::Client::HTTP's C<spawn> method takes a few named parameters:

=over 2

=item Agent => $user_agent_string

=item Agent => \@list_of_agents

If a UserAgent header is not present in the HTTP::Request, a random
one will be used from those specified by the C<Agent> parameter.  If
none are supplied, POE::Component::Client::HTTP will advertise itself
to the server.

C<Agent> may contain a reference to a list of user agents.  If this is
the case, PoCo::Client::HTTP will choose one of them at random for
each request.

=item Alias => $session_alias

C<Alias> sets the name by which the session will be known.  If no
alias is given, the component defaults to "weeble".  The alias lets
several sessions interact with HTTP components without keeping (or
even knowing) hard references to them.  It's possible to spawn several
HTTP components with different names.

=item CookieJar => $cookie_jar

C<CookieJar> sets the component's cookie jar.  It expects the cookie
jar to be a reference to a HTTP::Cookies object.

=item From => $admin_address

C<From> holds an e-mail address where the client's administrator
and/or maintainer may be reached.  It defaults to undef, which means
no From header will be included in requests.

=item MaxSize => OCTETS

C<MaxSize> specifies the largest response to accept from a server.
The content of larger responses will be truncated to OCTET octets.
This has been used to return the <head></head> section of web pages
without the need to wade through <body></body>.

=item NoProxy => [ $host_1, $host_2, ..., $host_N ]

=item NoProxy => "host1,host2,hostN"

C<NoProxy> specifies a list of server hosts that will not be proxied.
It is useful for local hosts and hosts that do not properly support
proxying.  If NoProxy is not specified, a list will be taken from the
NO_PROXY environment variable.

  NoProxy => [ "localhost", "127.0.0.1" ],
  NoProxy => "localhost,127.0.0.1",

=item Protocol => $http_protocol_string

C<Protocol> advertises the protocol that the client wishes to see.
Under normal circumstances, it should be left to its default value:
"HTTP/1.0".

=item Proxy => [ $proxy_host, $proxy_port ]

=item Proxy => $proxy_url

=item Proxy => $proxy_url,$proxy_url,...

C<Proxy> specifies one or more proxy hosts that requests will be
passed through.  If not specified, proxy servers will be taken from
the HTTP_PROXY (or http_proxy) environment variable.  No proxying will
occur unless Proxy is set or one of the environment variables exists.

The proxy can be specified either as a host and port, or as one or
more URLs.  Proxy URLs must specify the proxy port, even if it is 80.

  Proxy => [ "127.0.0.1", 80 ],
  Proxy => "http://127.0.0.1:80/",

C<Proxy> may specify multiple proxies separated by commas.
PoCo::Client::HTTP will choose proxies from this list at random.  This
is useful for load balancing requests through multiple gateways.

  Proxy => "http://127.0.0.1:80/,http://127.0.0.1:81/",

=item Streaming => OCTETS

C<Streaming> changes allows Client::HTTP to return large content in
chunks (of OCTETS octets each) rather than combine the entire content
into a single HTTP::Response object.

By default, Client::HTTP reads the entire content for a response into
memory before returning an HTTP::Response object.  This is obviously
bad for applications like streaming MP3 clients, because they often
fetch songs that never end.  Yes, they go on and on, my friend.

When C<Streaming> is set to nonzero, however, the response handler
receives chunks of up to OCTETS octets apiece.  The response handler
accepts slightly different parameters in this case.  ARG0 is also an
HTTP::Response object but it does not contain response content,
and ARG1 contains a a chunk of raw response
content, or undef if the stream has ended.

  sub streaming_response_handler {
    my $response_packet = $_[ARG1];
    my ($response, $data) = @$response_packet;
    print SAVED_STREAM $data if defined $data;
  }

=item FollowRedirects => $number_of_hops_to_follow

C<FollowRedirects> specifies how many redirects (e.g. 302 Moved) to
follow.  If not specified defaults to 0, and thus no redirection is
followed.  This maintains compatibility with the previous behavior,
which was not to follow redirects at all.

If redirects are followed, a response chain should be built, and can
be accessed through $response_object->previous(). See HTTP::Response
for details here.

=item Timeout => $query_timeout

C<Timeout> specifies the amount of time a HTTP request will wait for
an answer.  This defaults to 180 seconds (three minutes).

=back

Sessions communicate asynchronously with PoCo::Client::HTTP.  They
post requests to it, and it posts responses back.

Requests are posted to the component's "request" state.  They include
an HTTP::Request object which defines the request.  For example:

  $kernel->post(
    'ua', 'request',           # http session alias & state
    'response',                # my state to receive responses
    GET 'http://poe.perl.org', # a simple HTTP request
    'unique id',               # a tag to identify the request
    'progress',                # an event to indicate progress
  );

Requests include the state to which responses will be posted.  In the
previous example, the handler for a 'response' state will be called
with each HTTP response.  The "progress" handler is optional and if
installed, the component will provide progress metrics (see sample
handler below).

In addition to all the usual POE parameters, HTTP responses come with
two list references:

  my ($request_packet, $response_packet) = @_[ARG0, ARG1];

C<$request_packet> contains a reference to the original HTTP::Request
object.  This is useful for matching responses back to the requests
that generated them.

  my $http_request_object = $request_packet->[0];
  my $http_request_tag    = $request_packet->[1]; # from the 'request' post

C<$response_packet> contains a reference to the resulting
HTTP::Response object.

  my $http_response_object = $response_packet->[0];

Please see the HTTP::Request and HTTP::Response manpages for more
information.

There's also a pending_requests_count state that returns the number of
requests currently being processed.  To receive the return value, it
must be invoked with $kernel->call().

  my $count = $kernel->call('ua' => 'pending_requests_count');

The example progress handler shows how to calculate a percentage of
download completion.

  sub progress_handler {
    my $gen_args  = $_[ARG0];    # args passed to all calls
    my $call_args = $_[ARG1];    # args specific to the call

    my $req = $gen_args->[0];    # HTTP::Request object being serviced
    my $tag = $gen_args->[1];    # Request ID tag from.
    my $got = $call_args->[0];   # Number of bytes retrieved so far.
    my $tot = $call_args->[1];   # Total bytes to be retrieved.
    my $oct = $call_args->[2];   # Chunk of raw octets received this time.

    my $percent = $got / $tot * 100;

    printf(
      "-- %.0f%% [%d/%d]: %s\n", $percent, $got, $tot, $req->uri()
    );
  }

=head1 ENVIRONMENT

POE::Component::Client::HTTP uses two standard environment variables:
HTTP_PROXY and NO_PROXY.

HTTP_PROXY sets the proxy server that Client::HTTP will forward
requests through.  NO_PROXY sets a list of hosts that will not be
forwarded through a proxy.

See the Proxy and NoProxy constructor parameters for more information
about these variables.

=head1 SEE ALSO

This component is built upon HTTP::Request, HTTP::Response, and POE.
Please see its source code and the documentation for its foundation
modules to learn more.  If you want to use cookies, you'll need to
read about HTTP::Cookies as well.

Also see the test program, t/01_request.t, in the PoCo::Client::HTTP
distribution.

=head1 BUGS

HTTP/1.1 requests are not supported.

The following spawn() parameters are accepted but not yet implemented:
Timeout.

There is no support for CGI_PROXY or CgiProxy.

=head1 AUTHOR & COPYRIGHTS

POE::Component::Client::HTTP is Copyright 1999-2002 by Rocco Caputo.
All rights are reserved.  POE::Component::Client::HTTP is free
software; you may redistribute it and/or modify it under the same
terms as Perl itself.

Rocco may be contacted by e-mail via rcaputo@cpan.org.

=cut

# }}} POD
