# $Id$

package POE::Component::Client::HTTP;

# {{{ INIT

use strict;
#use bytes; # for utf8 compatibility

sub DEBUG      () { 0 }
sub DEBUG_DATA () { 0 }

use vars qw($VERSION);
$VERSION = '0.77';

use Carp qw(croak);
use HTTP::Response;

use POE::Component::Client::HTTP::RequestFactory;
use POE::Component::Client::HTTP::Request qw(:states :fields);

BEGIN {
  local $SIG{'__DIE__'} = 'DEFAULT';
  #TODO: move this to Client::Keepalive?
  # Allow more finely grained timeouts if Time::HiRes is available.
  eval {
    require Time::HiRes;
    Time::HiRes->import("time");
  };
}

use POE qw(
  Driver::SysRW Filter::Stream
  Filter::HTTPHead Filter::HTTPChunk
  Component::Client::Keepalive
);

my %te_filters = (
  chunked => 'POE::Filter::HTTPChunk',
);

my %supported_schemes = (
  http  => 1,
  https => 1,
);

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

  my $cm = delete $params{ConnectionManager};

  my $request_factory = POE::Component::Client::HTTP::RequestFactory->new(
    \%params
  );

  croak(
    "$type doesn't know these parameters: ",
    join(', ', sort keys %params)
  ) if scalar keys %params;

  POE::Session->create(
    inline_states => {
      _start  => \&poco_weeble_start,
      _stop   => \&poco_weeble_stop,
      _child  => sub { },

      # Public interface.
      request                => \&poco_weeble_request,
      pending_requests_count => \&poco_weeble_pending_requests_count,
      'shutdown'             => \&poco_weeble_shutdown,
      cancel                 => \&poco_weeble_cancel,

      # Client::Keepalive interface.
      got_connect_done  => \&poco_weeble_connect_done,

      # ReadWrite interface.
      got_socket_input  => \&poco_weeble_io_read,
      got_socket_flush  => \&poco_weeble_io_flushed,
      got_socket_error  => \&poco_weeble_io_error,

      # I/O timeout.
      got_timeout       => \&poco_weeble_timeout,
      remove_request    => \&poco_weeble_remove_request,
    },
    heap => {
      alias        => $alias,
      factory      => $request_factory,
      cm           => $cm,
      is_shut_down => 0,
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

  # have to do this here because it wants a current_session
  $heap->{cm} = POE::Component::Client::Keepalive->new(
    timeout => $heap->{factory}->timeout,
  ) unless ($heap->{cm});
}

# }}} poco_weeble_start
#------------------------------------------------------------------------------
# {{{ poco_weeble_stop

sub poco_weeble_stop {
  my $heap = $_[HEAP];
  my $request = delete $heap->{request};

  foreach my $request_rec (values %$request) {
    $request_rec->remove_timeout();
  }

  DEBUG and warn "Client::HTTP (alias=$heap->{alias}) stopped.";
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
    $response_event, $http_request, $tag, $progress_event,
    $proxy_override
  ) = @_[KERNEL, HEAP, SENDER, ARG0, ARG1, ARG2, ARG3, ARG4];

  unless ($supported_schemes{$http_request->uri->scheme}) {
    my $rsp = HTTP::Response->new(
       400 => 'Bad Request', [],
       "<html>\n"
       . "<HEAD><TITLE>Error: Bad Request</TITLE></HEAD>\n"
       . "<BODY>\n"
       . "<H1>Error: Bad Request</H1>\n"
       . "Unsupported URI scheme\n"
       . "</BODY>\n"
       . "</HTML>\n"
      );
    $rsp->request($http_request);
    $kernel->post($sender, $response_event, [$http_request, $tag], [$rsp]);
    return;
  }

  if ($heap->{is_shut_down}) {
    my $rsp = HTTP::Response->new(
       408 => 'Request timed out (component shut down)', [],
       "<html>\n"
       . "<HEAD><TITLE>Error: Request timed out (component shut down)"
       . "</TITLE></HEAD>\n"
       . "<BODY>\n"
       . "<H1>Error: Request Timeout</H1>\n"
       . "Request timed out (component shut down)\n"
       . "</BODY>\n"
       . "</HTML>\n"
      );
    $rsp->request($http_request);
    $kernel->post($sender, $response_event, [$http_request, $tag], [$rsp]);
    return;
  }

  if (defined $proxy_override) {
    POE::Component::Client::HTTP::RequestFactory->parse_proxy($proxy_override);
  }

  my $request = $heap->{factory}->create_request(
    $http_request, $response_event, $tag, $progress_event,
    $proxy_override, $sender
  );
  $heap->{request}->{$request->ID} = $request;
  $heap->{request_to_id}->{$http_request} = $request->ID;

  my @timeout;
  if ($heap->{factory}->timeout()) {
    @timeout = (
      timeout => $heap->{factory}->timeout()
    );
  }

  my $cm_req_id;
  eval {
      # get a connection from Client::Keepalive
      $request->[REQ_CONN_ID] = $heap->{cm}->allocate(
        scheme  => $request->scheme,
        addr    => $request->host,
        port    => $request->port,
        context => $request->ID,
        event   => 'got_connect_done',
        @timeout,
      );
  };
  if ($@) {
      delete $heap->{request}->{$request->ID};
      # we can reach here for things like host being invalid.
      $request->error(400, $@);
  }
}

# }}} poco_weeble_request

#------------------------------------------------------------------------------
# {{{ poco_weeble_connect_done

sub poco_weeble_connect_done {
  my ($heap, $response) = @_[HEAP, ARG0];

  my $connection = $response->{'connection'};
  my $request_id = $response->{'context'};

  if (defined $connection) {
    DEBUG and warn "CON: request $request_id connected ok...";

    my $request = $heap->{request}->{$request_id};

    my $block_size = $heap->{factory}->block_size;

    # get wheel from the connection
    my $new_wheel = $connection->start(
      Driver       => POE::Driver::SysRW->new(BlockSize => $block_size),
      InputFilter  => POE::Filter::HTTPHead->new(),
      OutputFilter => POE::Filter::Stream->new(),
      InputEvent   => 'got_socket_input',
      FlushedEvent => 'got_socket_flush',
      ErrorEvent   => 'got_socket_error',
    );

    DEBUG and warn "CON: request $request_id uses wheel ", $new_wheel->ID;

    # Add the new wheel ID to the lookup table.
    $heap->{wheel_to_request}->{ $new_wheel->ID() } = $request_id;

    $request->[REQ_CONNECTION] = $connection;
    $request->create_timer($heap->{factory}->timeout);
    $request->send_to_wheel;
  }
  else {
    DEBUG and warn(
      "CON: Error connecting for request $request_id --- ", $_[SENDER]->ID
    );

    my ($operation, $errnum, $errstr) = (
      $response->{function},
      $response->{error_num} || '??',
      $response->{error_str}
    );

    DEBUG and warn(
      "CON: request $request_id encountered $operation error " .
      "$errnum: $errstr"
    );

    DEBUG and warn "I/O: removing request $request_id";
    my $request = delete $heap->{request}->{$request_id};
    $request->remove_timeout();

    # Post an error response back to the requesting session.
    $request->connect_error("$operation error $errnum: $errstr");
  }
}

# }}} poco_weeble_connect_done

# {{{ poco_weeble_timeout

sub poco_weeble_timeout {
  my ($kernel, $heap, $request_id) = @_[KERNEL, HEAP, ARG0];

  DEBUG and warn "T/O: request $request_id timed out";

  # Discard the request.  Keep a copy for a few bits of cleanup.
  DEBUG and warn "I/O: removing request $request_id";
  my $request = delete $heap->{request}->{$request_id};

  unless (defined $request) {
    die(
      "T/O: unexpectedly undefined request for id $request_id\n",
      "T/O: known request IDs: ", join(", ", keys %{$heap->{request}}), "\n",
      "...",
    );
  }

  DEBUG and warn "T/O: request $request_id has timer ", $request->timer;
  $request->remove_timeout();

  # There's a wheel attached to the request.  Shut it down.
  if (defined(my $wheel = $request->wheel())) {
    my $wheel_id = $wheel->ID();
    DEBUG and warn "T/O: request $request_id is wheel $wheel_id";

    # Shut down the connection so it's not reused.
    $wheel->shutdown_input();
    delete $heap->{wheel_to_request}->{$wheel_id};
    delete $heap->{request_to_id}->{$request->[REQ_REQUEST]};
  }

  DEBUG and do {
    die( "T/O: request $request_id is unexpectedly zero" )
      unless $request->[REQ_STATE];
    warn "T/O: request_state = " . sprintf("%#04x\n", $request->[REQ_STATE]);
  };

  # Hey, we haven't sent back a response yet!
  unless ($request->[REQ_STATE] & (RS_REDIRECTED | RS_POSTED)) {

    # Well, we have a response.  Isn't that nice?  Let's send it.
    if ($request->[REQ_STATE] & (RS_IN_CONTENT | RS_DONE)) {
      _finish_request($heap, $request, 0);
      return;
    }

    # Post an error response back to the requesting session.
    DEBUG and warn "I/O: Disconnect, keepalive timeout or HTTP/1.0.";
    $request->error(408, "Request timed out") if $request->[REQ_STATE];
    return;
  }
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

  DEBUG and warn(
    "I/O: wheel $wheel_id (request $request_id) flushed its request..."
  );

  my $request = $heap->{request}->{$request_id};
  $request->[REQ_STATE] ^= RS_SENDING;
  $request->[REQ_STATE] = RS_IN_HEAD;
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
    warn "I/O: wheel $wheel_id encountered $operation error $errnum: $errstr";

  # Drop the wheel.
  my $request_id = delete $heap->{wheel_to_request}->{$wheel_id};
  #K or die "!!!: unexpectedly undefined request ID" unless defined $request_id;

  if ($request_id) {

    DEBUG and warn "I/O: removing request $request_id";
    my $request = delete $heap->{request}->{$request_id};
    delete $heap->{request_to_id}{$request->[REQ_REQUEST]};
    $request->remove_timeout;

    # Otherwise the remote end simply closed.  If we've got a
    # pending response, then post it back to the client.
    DEBUG and warn "STATE is ", $request->[REQ_STATE];

    # except when we're redirected
    return if ($request->[REQ_STATE] & RS_REDIRECTED);

    # If there was a non-zero error, then something bad happened.  Post
    # an error response back, if we haven't posted anything before.
    if ($errnum) {
      unless ($request->[REQ_STATE] & RS_POSTED) {
        $request->error(400, "$operation error $errnum: $errstr");
      }
      return;
    }

    if (
      $request->[REQ_STATE] & (RS_IN_CONTENT | RS_DONE) and
      not $request->[REQ_STATE] & RS_POSTED
    ) {
      _finish_request($heap, $request, 0);
      return;
    }
    elsif ($request->[REQ_STATE] & RS_POSTED) {
      DEBUG and warn "I/O: Disconnect, remote keepalive timeout or HTTP/1.0.";
      return;
    }
    elsif (not defined $request->[REQ_RESPONSE]) {
      # never got a response, check for pending data indicating
      # a LF-free HTTP 0.9 response
      my $lines = $request->wheel->get_input_filter()->get_pending();
      my $text = join '' => @$lines;
      DEBUG and warn "Got ", length($text), " bytes of data without LF.";
      if ($text =~ /\S/) {
        # generate response
        DEBUG and warn(
          "Generating HTTP response for HTTP/0.9 response without LF."
        );
        $request->[REQ_RESPONSE] = HTTP::Response->new(
          200, 'OK', [ 'Content-Type' => 'text/html' ], $text
        );
        $request->[REQ_RESPONSE]->protocol('HTTP/0.9');
        $request->[REQ_RESPONSE]->request($request->[REQ_REQUEST]);
        $request->[REQ_STATE] = RS_DONE;
        $request->return_response;
        return;
      }
    }

    # We haven't built a proper response.  Send back an error.
    $request->error (400, "incomplete response $request_id");
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

  DEBUG and warn "I/O: wheel $wheel_id got input...";
  DEBUG_DATA and warn (ref($input) ? $input->as_string : _hexdump($input));

  # TODO - So, which is it?  Return, or die?
  return unless defined $request_id;
  die unless defined $request_id;

  my $request = $heap->{request}->{$request_id};
  return unless defined $request;
  DEBUG and warn(
    "REQUEST $request_id is $request <" . $request->[REQ_REQUEST]->uri . ">"
  );

  # Reset the timeout if we get data.
  $kernel->delay_adjust($request->timer, $heap->{factory}->timeout);

  if ($request->[REQ_STATE] & RS_REDIRECTED) {
    DEBUG and warn "input for request that was redirected";
    return;
  }

# {{{ HEAD

  # The very first line ought to be status.  If it's not, then it's
  # part of the content.
  if ($request->[REQ_STATE] & RS_IN_HEAD) {
    if (defined $input) {
      $input->request ($request->[REQ_REQUEST]);
      #warn(
      #  "INPUT for ", $request->[REQ_REQUEST]->uri, " is \n",$input->as_string
      #)
    }
    else {
      #warn "NO INPUT";
    }

    # FIXME: LordVorp gets here without $input being a HTTP::Response.
    # FIXME: This happens when the response is HTTP/0.9 and doesn't
    # include a status line.  See t/53_response_parser.t.
    $request->[REQ_RESPONSE] = $input;

    # Some responses are without content by definition
    # FIXME: #12363
    #        Make sure we finish even when it isn't one of these,
    #        but there is no content.
    if (
      $request->[REQ_REQUEST]->method eq 'HEAD'
      or $input->code =~ /^(?:1|[23]04)/
      or (
        defined($input->content_length())
        and $input->content_length() == 0
      )
    ) {
      if (_try_redirect($request_id, $input, $request)) {
        my $old_request = delete $heap->{request}->{$request_id};
        delete $heap->{wheel_to_request}->{$wheel_id};
        if (defined $old_request) {
          DEBUG and warn "I/O: removed request $request_id";
          delete $heap->{request_to_id}{$old_request->[REQ_REQUEST]};
          $old_request->remove_timeout();
          $old_request->[REQ_CONNECTION] = undef;
        }
        return;
      }
      $request->[REQ_STATE] |= RS_DONE;
      $request->remove_timeout();
      _finish_request($heap, $request, 1);
      return;
    }
    else {
      $request->[REQ_STATE] |= RS_IN_CONTENT;
      $request->[REQ_STATE] &= ~RS_IN_HEAD;
      #FIXME: probably want to find out when the content from this
      #       request is in, and only then do the new request, so we
      #       can reuse the connection.
      if (_try_redirect($request_id, $input, $request)) {
        my $old_request = delete $heap->{request}->{$request_id};
        delete $heap->{wheel_to_request}->{$wheel_id};
        if (defined $old_request) {
          DEBUG and warn "I/O: removed request $request_id";
          delete $heap->{request_to_id}{$old_request->[REQ_REQUEST]};
          $old_request->remove_timeout();
          $old_request->[REQ_CONNECTION]->close();
          $old_request->[REQ_CONNECTION] = undef;
        }
        return;
      }

      # RFC 2616 14.41:  If multiple encodings have been applied to an
      # entity, the transfer-codings MUST be listed in the order in
      # which they were applied.

      my ($filter, @filters);

      my $te = $input->header('Transfer-Encoding');
      if (defined $te) {
        my @te = split(/\s*,\s*/, lc($te));

        while (@te and exists $te_filters{$te[-1]}) {
          my $encoding = pop @te;
          my $fclass = $te_filters{$encoding};
          push @filters, $fclass->new();
        }

        if (@te) {
          $input->header('Transfer-Encoding', join(', ', @te));
        }
        else {
          $input->header('Transfer-Encoding', undef);
        }
      }

      if (@filters > 1) {
        $filter = POE::Filter::Stackable->new( Filters => \@filters );
      }
      elsif (@filters) {
        $filter = $filters[0];
      }
      else {
        $filter = POE::Filter::Stream->new;
      }

      # do this last, because it triggers a read
      $request->wheel->set_input_filter($filter);
    }
    return;
  }

# }}} HEAD

# {{{ content

  # We're in a content state.
  if ($request->[REQ_STATE] & RS_IN_CONTENT) {
    if (ref($input) and UNIVERSAL::isa($input, 'HTTP::Response')) {
      # there was a problem in the input filter
      # $request->close_connection;
    }
    else {
      my $is_done = $request->add_content ($input);
    }
  }

# }}} content

# {{{ deliver reponse if complete

# POST response without disconnecting
  if (
    $request->[REQ_STATE] & RS_DONE and
    not $request->[REQ_STATE] & RS_POSTED
  ) {
    $request->remove_timeout;
    _finish_request($heap, $request, 1);
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

# Check for and handle redirect.  Returns true if redirect should
# occur, or false if there's no redirect.

sub _try_redirect {
  my ($request_id, $input, $request) = @_;

  if (my $newrequest = $request->check_redirect) {
    DEBUG and warn(
      "Redirected $request_id ", $input->code, " to <",
      $newrequest->uri, ">"
    );
    my @proxy;
    if ($request->[REQ_USING_PROXY]) {
      push @proxy, (
        'http://' .  $request->host .  ':' .  $request->port .  '/'
      );
    }

    $poe_kernel->yield(
      request =>
      $request,
      $newrequest,
      "_redir_".$request->ID,
      $request->[REQ_PROG_POSTBACK],
      @proxy
    );

    return 1;
  }

  return;
}

# Complete a request. This was moved out of poco_weeble_io_error(). This is
# not a POE function.
# {{{ _finish_request

sub _finish_request {
  my ($heap, $request, $wait) = @_;

  my $request_id = $request->ID;
  if (DEBUG) {
    my ($pkg, $file, $line) = caller();
    warn(
      "XXX: calling _finish_request(request id = $request_id)" .
      "at $file line $line"
    );
  }

  # XXX What does this do?
  $request->add_eof;

  # KeepAlive: added the RS_POSTED flag
  $request->[REQ_STATE] |= RS_POSTED;

  my $wheel_id = defined $request->wheel ? $request->wheel->ID : "(undef)";
  DEBUG and warn "Wheel from request is ", $wheel_id;
  # clean up the request
  my $address = "$request->[REQ_HOST]:$request->[REQ_PORT]";

  DEBUG and warn "address is $address";

  if ($wait) {
    #wait a bit with removing the request, so there's
    #time to receive the EOF event in case the connection
    #gets closed.
    my $alarm_id = $poe_kernel->delay_set('remove_request', 0.5, $request_id);

    # remove the old timeout first
    DEBUG and warn "delay_set; now remove_timeout()";
    $request->remove_timeout();
    DEBUG and warn "removed timeout; now timer()";
    $request->timer($alarm_id);
  }
  else {
    # Virtually identical to _remove_request.
    # TODO - Make a common sub to handle both cases?
    my $request = delete $heap->{request}->{$request_id};
    if (defined $request) {
      DEBUG and warn "I/O: removing request $request_id";
      $request->remove_timeout();
      if (my $wheel = $request->wheel) {
        delete $heap->{wheel_to_request}->{$wheel->ID};
        delete $heap->{request_to_id}{$request->[REQ_REQUEST]};
      }
    }
  }
}

# }}} _finish_request

#{{{ _remove_request
sub poco_weeble_remove_request {
  my ($kernel, $heap, $request_id) = @_[KERNEL, HEAP, ARG0];

  my $request = delete $heap->{request}->{$request_id};
  if (defined $request) {
    DEBUG and warn "I/O: removed request $request_id";
    $request->remove_timeout();
    if (my $wheel = $request->wheel) {
      delete $heap->{wheel_to_request}->{$wheel->ID};
      delete $heap->{request_to_id}{$request->[REQ_REQUEST]};
    }
  }
}
#}}} _remove_request

# Cancel a single request by HTTP::Request object.

sub poco_weeble_cancel {
  my ($kernel, $heap, $request) = @_[KERNEL, HEAP, ARG0];
  my $request_id = $heap->{request_to_id}{$request};
  return unless defined $request_id;
  _internal_cancel(
    $heap, $request_id, 408, "Request timed out (request canceled)"
  );
}

sub _internal_cancel {
  my ($heap, $request_id, $code, $message) = @_;

  my $request = delete $heap->{request}{$request_id};
  return unless defined $request;

  DEBUG and warn "SHT: Shutdown is canceling request $request_id";
  $request->remove_timeout();

  if (my $wheel = $request->wheel) {
    my $wheel_id = $wheel->ID;
    DEBUG and warn "SHT: Request $request_id canceling wheel $wheel_id";
    delete $heap->{wheel_to_request}{$wheel_id};
    delete $heap->{request_to_id}{$request->[REQ_REQUEST]};
    $wheel = undef;
  }

  if ($request->[REQ_CONNECTION]) {
    $request->[REQ_CONNECTION]->close();
    $request->[REQ_CONNECTION] = undef;
  }
  else {
    # Didn't connect yet; inform connection manager to cancel
    # connection request.
    $heap->{cm}->deallocate($request_id);
  }

  unless ($request->[REQ_STATE] & RS_POSTED) {
    $request->error(408, "Request timed out (component shut down)");
  }
}

# Shut down the entire component.
sub poco_weeble_shutdown {
  my ($kernel, $heap) = @_[KERNEL, HEAP];

  $heap->{is_shut_down} = 1;

  my @request_ids = keys %{$heap->{request}};
  foreach my $request_id (@request_ids) {
    _internal_cancel(
      $heap, $request_id, 408, "Request timed out (component shut down)"
    );
  }

  # Shut down the connection manager subcomponent.
  if (defined $heap->{cm}) {
    DEBUG and warn "SHT: Client::HTTP shutting down Client::Keepalive";
    $heap->{cm}->shutdown();
    delete $heap->{cm};
  }

  # Final cleanup of this component.
  $kernel->alias_remove($heap->{alias});
}

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
    Protocol  => 'HTTP/0.9',            # defaults to 'HTTP/1.1'
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

=head1 CONSTRUCTOR

=head2 spawn

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

=item ConnectionManager => $poco_client_keepalive

C<ConnectionManager> sets this component's connection pool manager.
It expects the connection manager to be a reference to a
POE::Component::Client::Keepalive object.  The HTTP client component
will call C<allocate()> on the connection manager itself so you should
not have done this already.

  my $pool = POE::Component::Client::Keepalive->new(
    keep_alive    => 10, # seconds to keep connections alive
    max_open      => 100, # max concurrent connections - total
    max_per_host  => 20, # max concurrent connections - per host
    timeout       => 30, # max time (seconds) to establish a new connection
  );

  POE::Component::Client::HTTP->spawn(
    # ...
    ConnectionManager => $pool,
    # ...
  );

See L<POE::Component::Client::Keepalive> for more information.

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
"HTTP/1.1".

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

=head1 ACCEPTED EVENTS

Sessions communicate asynchronously with PoCo::Client::HTTP.  They
post requests to it, and it posts responses back.

=head2 request

Requests are posted to the component's "request" state.  They include
an HTTP::Request object which defines the request.  For example:

  $kernel->post(
    'ua', 'request',           # http session alias & state
    'response',                # my state to receive responses
    GET 'http://poe.perl.org', # a simple HTTP request
    'unique id',               # a tag to identify the request
    'progress',                # an event to indicate progress
    'http://1.2.3.4:80/'       # proxy to use for this request
  );

Requests include the state to which responses will be posted.  In the
previous example, the handler for a 'response' state will be called
with each HTTP response.  The "progress" handler is optional and if
installed, the component will provide progress metrics (see sample
handler below).  The "proxy" parameter is optional and if not defined,
a default proxy will be used if configured.  No proxy will be used if
neither a default one nor a "proxy" parameter is defined.

=head2 pending_requests_count

There's also a pending_requests_count state that returns the number of
requests currently being processed.  To receive the return value, it
must be invoked with $kernel->call().

  my $count = $kernel->call('ua' => 'pending_requests_count');

=head2 cancel

Cancel a specific HTTP request.  Requires a reference to the original
request (blessed or stringified) so it knows which one to cancel.  See
L<progress handler> below for notes on canceling streaming requests.

To cancel a request based on its blessed HTTP::Request object:

  $kernel->post( component => cancel => $http_request );

To cancel a request based on its stringified HTTP::Request object:

  $kernel->post( component => cancel => "$http_request" );

=head2 shutdown

Responds to all pending requests with 408 (request timeout), and then
shuts down the component and all subcomponents.

=head1 SENT EVENTS

=head2 response handler

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

=head2 progress handler

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

    # To cancel the request:
    # $_[KERNEL]->post( component => cancel => $req );
  }

=head3 DEPRECATION WARNING

The third return argument (the raw octets received) has been deprecated.
Instead of it, use the Streaming parameter to get chunks of content
in the response handler.

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

There is no support for CGI_PROXY or CgiProxy.

Secure HTTP (https) proxying is not supported at this time.

There is no object oriented interface.  See
L<POE::Component::Client::Keepalive> and
L<POE::Component::Client::DNS> for examples of a decent OO interface.

=head1 AUTHOR & COPYRIGHTS

POE::Component::Client::HTTP is

=over 2

=item

Copyright 1999-2006 Rocco Caputo

=item

Copyright 2004 Rob Bloodgood

=item

Copyright 2004-2005 Martijn van Beers

=back

All rights are reserved.  POE::Component::Client::HTTP is free
software; you may redistribute it and/or modify it under the same
terms as Perl itself.

=head1 CONTACT

Rocco may be contacted by e-mail via L<mailto:rcaputo@cpan.org>, and
Martijn may be contacted by email via L<mailto:martijn@cpan.org>.

The preferred way to report bugs or requests is through RT though.
See L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=POE-Component-Client-HTTP>
or mail L<mailto:bug-POE-Component-Client-HTTP@rt.cpan.org>

For questions, try the L<POE> mailing list (poe@perl.org)

=cut

# }}} POD
