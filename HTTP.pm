# $Id$
# License and documentation are after __END__.

package POE::Component::Client::HTTP;

use strict;

sub DEBUG () { 0 }

use vars qw($VERSION);
$VERSION = '0.42';

use Carp qw(croak);
use POSIX;
use HTTP::Response;

use POE qw( Wheel::SocketFactory Wheel::ReadWrite
            Driver::SysRW Filter::Stream
          );

sub REQ_POSTBACK      () {  0 }
sub REQ_WHEEL         () {  1 }
sub REQ_REQUEST       () {  2 }
sub REQ_STATE         () {  3 }
sub REQ_RESPONSE      () {  4 }
sub REQ_BUFFER        () {  5 }
sub REQ_LAST_HEADER   () {  6 }
sub REQ_OCTETS_GOT    () {  7 }
sub REQ_NEWLINE       () {  8 }
sub REQ_TIMER         () {  9 }
sub REQ_PROG_POSTBACK () { 10 }

sub RS_CONNECT      () { 0x01 }
sub RS_SENDING      () { 0x02 }
sub RS_IN_STATUS    () { 0x04 }
sub RS_IN_HEADERS   () { 0x08 }
sub RS_IN_CONTENT   () { 0x10 }
sub RS_DONE         () { 0x20 }

# Unique request ID, independent of wheel and timer IDs.

my $request_seq = 0;

#------------------------------------------------------------------------------
# Spawn a new PoCo::Client::HTTP session.  This basically is a
# constructor, but it isn't named "new" because it doesn't create a
# usable object.  Instead, it spawns the object off as a separate
# session.

sub spawn {
  my $type = shift;

  croak "$type requires an even number of parameters" if @_ % 2;

  my %params = @_;

  my $alias = delete $params{Alias};
  $alias = 'weeble' unless defined $alias and length $alias;

  my $timeout = delete $params{Timeout};
  $timeout = 180 unless defined $timeout and $timeout >= 0;

  my $agent = delete $params{Agent};
  $agent = sprintf( 'POE-Component-Client-HTTP/%.03f (perl; N; POE; en)',
                    $VERSION,
                  ) unless defined $agent and length $agent;

  my $max_size = delete $params{MaxSize};

  my $protocol = delete $params{Protocol};
  $protocol = 'HTTP/1.0' unless defined $protocol and length $protocol;

  my $cookie_jar = delete $params{CookieJar};
  my $from       = delete $params{From};
  my $proxy      = delete $params{Proxy};
  my $no_proxy   = delete $params{NoProxy};

  croak( "$type doesn't know these parameters: ",
         join(', ', sort keys %params)
       ) if scalar keys %params;

  POE::Session->create
    ( inline_states =>
      { _start  => \&poco_weeble_start,
        _stop   => \&poco_weeble_stop,

        # Public interface.
        request => \&poco_weeble_request,

        # SocketFactory interface.
        got_connect_done  => \&poco_weeble_connect_ok,
        got_connect_error => \&poco_weeble_connect_error,

        # ReadWrite interface.
        got_socket_input  => \&poco_weeble_io_read,
        got_socket_flush  => \&poco_weeble_io_flushed,
        got_socket_error  => \&poco_weeble_io_error,

        # I/O timeout.
        got_timeout       => \&poco_weeble_timeout,

        # Sorry, don't handle signals.
        _signal           => sub { 0 },
      },
      args => [ $alias,      # ARG0
                $timeout,    # ARG1
                $agent,      # ARG2
                $cookie_jar, # ARG3
                $from,       # ARG4
                $proxy,      # ARG5
                $no_proxy,   # ARG6
                $protocol,   # ARG7
                $max_size,   # ARG8
              ],
    );

  undef;
}

#------------------------------------------------------------------------------

sub poco_weeble_start {
  my ( $kernel, $heap,
       $alias, $timeout, $agent, $cookie_jar, $from,
       $proxy, $no_proxy, $protocol, $max_size
     ) = @_[KERNEL, HEAP, ARG0..$#_];

  DEBUG and do {
    sub no_undef { (defined $_[0]) ? $_[0] : '(undef)' };
    warn ",--- starting a http client component ----\n";
    warn "| alias     : $alias\n";
    warn "| timeout   : $timeout\n";
    warn "| agent     : $agent\n";
    warn "| protocol  : $protocol\n";
    warn "| max_size  : ", &no_undef($max_size), "\n";
    warn "| cookie_jar: ", &no_undef($cookie_jar), "\n";
    warn "| from      : ", &no_undef($from), "\n";
    warn "| proxy     : ", &no_undef($proxy), "\n";
    warn "| no_proxy  : ", &no_undef($no_proxy), "\n";
    warn "'-----------------------------------------\n";
  };

  $heap->{alias}      = $alias;
  $heap->{timeout}    = $timeout;
  $heap->{cookie_jar} = $cookie_jar;
  $heap->{proxy}      = $proxy;
  $heap->{no_proxy}   = $no_proxy;

  $heap->{agent}      = $agent;
  $heap->{from}       = $from;
  $heap->{protocol}   = $protocol;

  $heap->{max_size}   = $max_size;

  $kernel->alias_set($alias);
}

#------------------------------------------------------------------------------

sub poco_weeble_stop {
  my $heap = shift;
  delete $heap->{request};

  DEBUG and warn "weeble stopped.\n";
}

#------------------------------------------------------------------------------

sub poco_weeble_request {
  my ( $kernel, $heap, $sender,
       $response_event, $http_request, $tag, $progress_event
     ) = @_[KERNEL, HEAP, SENDER, ARG0, ARG1, ARG2, ARG3];

  # Add a protocol if one isn't included.
  $http_request->protocol( $heap->{protocol} )
    unless ( defined $http_request->protocol()
             and length $http_request->protocol()
           );

  # Get the host and port from the request object.
  my ($host, $port);
  eval {
    $host = $http_request->uri()->host();
    $port = $http_request->uri()->port();
  };
  warn($@), return if $@;

  # Add a host header if one isn't included.
  $http_request->header( Host => "$host:$port" )
    unless ( defined $http_request->header('Host')
             and length $http_request->header('Host')
           );

  # Add an agent header if one isn't included.
  $http_request->user_agent( $heap->{agent} )
    unless ( defined $http_request->user_agent
             and length $http_request->user_agent
           );

  # Add a from header if one isn't included.
  if (defined $heap->{from} and length $heap->{from}) {
    $http_request->from( $heap->{from} )
      unless ( defined $http_request->from
               and length $http_request->from
             );
  }

  # Create a progress postback if requested.
  my $progress_postback;
  $progress_postback = $sender->postback($progress_event, $http_request, $tag)
    if defined $progress_event;

  # If we have a cookie jar, have it frob our headers.  LWP rocks!
  if (defined $heap->{cookie_jar}) {
    $heap->{cookie_jar}->add_cookie_header($http_request);
  }

  DEBUG and warn "weeble got a request...\n";

  # Get a unique request ID.
  my $request_id = ++$request_seq;

  # Create a socket factory.
  my $socket_factory =
    POE::Wheel::SocketFactory->new
      ( RemoteAddress => $host,
        RemotePort    => $port,
        SuccessEvent  => 'got_connect_done',
        FailureEvent  => 'got_connect_error',
      );

  # Create a timeout timer.
  my $timer_id = $kernel->delay_set( got_timeout => $heap->{timeout} =>
                                     $request_id
                                   );

  # Record information about the request.

  $heap->{request}->{$request_id} =
    [ $sender->postback( $response_event, $http_request, $tag ), # REQ_POSTBACK
      $socket_factory,    # REQ_WHEEL
      $http_request,      # REQ_REQUEST
      RS_CONNECT,         # REQ_STATE
      undef,              # REQ_RESPONSE
      '',                 # REQ_BUFFER
      '',                 # REQ_LAST_HEADER
      0,                  # REQ_OCTETS_GOT
      "\x0D\x0A",         # REQ_NEWLINE
      $timer_id,          # REQ_TIMER
      $progress_postback, # REQ_PROG_POSTBACK
    ];

  # Cross-reference the wheel and timer IDs back to the request.
  $heap->{timer_to_request}->{$timer_id} = $request_id;
  $heap->{wheel_to_request}->{$socket_factory->ID()} = $request_id;

  DEBUG and
    warn( "wheel ", $socket_factory->ID,
          " is connecting to $host : $port ...\n"
        );
}

#------------------------------------------------------------------------------

sub poco_weeble_connect_ok {
  my ($heap, $socket, $wheel_id) = @_[HEAP, ARG0, ARG3];

  DEBUG and warn "wheel $wheel_id connected ok...\n";

  # Remove the old wheel ID from the look-up table.
  my $request_id = delete $heap->{wheel_to_request}->{$wheel_id};
  die unless defined $request_id;

  my $request = $heap->{request}->{$request_id};

  # Make a ReadWrite wheel to interact on the socket.
  my $new_wheel = POE::Wheel::ReadWrite->new
    ( Handle       => $socket,
      Driver       => POE::Driver::SysRW->new(),
      Filter       => POE::Filter::Stream->new(),
      InputEvent   => 'got_socket_input',
      FlushedEvent => 'got_socket_flush',
      ErrorEvent   => 'got_socket_error',
    );

  # Add the new wheel ID to the lookup table.

  $heap->{wheel_to_request}->{ $new_wheel->ID() } = $request_id;

  # Switch wheels.  This is a bit cumbersome, but it works around a
  # bug in older versions of POE.

  undef $request->[REQ_WHEEL];
  $request->[REQ_WHEEL] = $new_wheel;

  # We're now in a sending state.
  $request->[REQ_STATE] = RS_SENDING;

  # Put the request.  HTTP::Request's as_string() method isn't quite
  # right.  It uses the full URL on the request line, so we have to
  # put the request in pieces.

  my $http_request = $request->[REQ_REQUEST];
  my $request_string =
    ( $http_request->method() . ' ' .
      $http_request->uri()->path_query() . ' ' .
      $http_request->protocol() . "\x0D\x0A" .
      $http_request->headers_as_string("\x0D\x0A") . "\x0D\x0A" .
      $http_request->content() # . "\x0D\x0A"
    );

  DEBUG and do {
    my $formatted_request_string = $request_string;
    $formatted_request_string =~ s/([^\n])$/$1\n/;
    $formatted_request_string =~ s/^/| /mg;
    print ",----- SENDING REQUEST ", '-' x 56, "\n";
    print $formatted_request_string;
    print "`", '-' x 78, "\n";
  };

  $request->[REQ_WHEEL]->put( $request_string );
}

#------------------------------------------------------------------------------

sub poco_weeble_connect_error {
  my ($kernel, $heap, $operation, $errnum, $errstr, $wheel_id) =
    @_[KERNEL, HEAP, ARG0..ARG3];

  DEBUG and
    warn "wheel $wheel_id encountered $operation error $errnum: $errstr\n";

  # Drop the wheel and its cross-references.
  my $request_id = delete $heap->{wheel_to_request}->{$wheel_id};
  die unless defined $request_id;

  my $request = delete $heap->{request}->{$request_id};

  my $alarm_id = $request->[REQ_TIMER];
  if (delete $heap->{timer_to_request}->{ $alarm_id }) {
    $kernel->alarm_remove( $alarm_id );
  }

  # Post an error response back to the requesting session.
  $request->[REQ_POSTBACK]->
    ( HTTP::Response->new( 400, "$operation error $errnum: $errstr" )
    );
}

#------------------------------------------------------------------------------

sub poco_weeble_timeout {
  my ($kernel, $heap, $request_id) = @_[KERNEL, HEAP, ARG0];

  DEBUG and warn "request $request_id timed out\n";

  # Drop the wheel and its cross-references.
  my $request = delete $heap->{request}->{$request_id};

  if (defined $request->[REQ_WHEEL]) {
    delete $heap->{wheel_to_request}->{ $request->[REQ_WHEEL]->ID() };
  }

  # No need to remove the alarm here because it's already gone.
  delete $heap->{timer_to_request}->{ $request->[REQ_TIMER] };

  # Post an error response back to the requesting session.
  $request->[REQ_POSTBACK]->
    ( HTTP::Response->new( 400, "Request timed out" )
    );
}

#------------------------------------------------------------------------------

sub poco_weeble_io_flushed {
  my ($heap, $wheel_id) = @_[HEAP, ARG0];

  DEBUG and warn "wheel $wheel_id flushed its request...\n";

  # We sent the request.  Now we're looking for a response.  It may be
  # bad to assume we won't get a response until a request has flushed.
  my $request_id = $heap->{wheel_to_request}->{$wheel_id};
  die unless defined $request_id;
  $heap->{request}->{$request_id}->[REQ_STATE] = RS_IN_STATUS;
}

#------------------------------------------------------------------------------

sub poco_weeble_io_error {
  my ($kernel, $heap, $operation, $errnum, $errstr, $wheel_id) =
    @_[KERNEL, HEAP, ARG0..ARG3];

  DEBUG and
    warn "wheel $wheel_id encountered $operation error $errnum: $errstr\n";

  # Drop the wheel.
  my $request_id = delete $heap->{wheel_to_request}->{$wheel_id};
  my $request = delete $heap->{request}->{$request_id};

  # Stop the timeout timer for this wheel, too.
  my $alarm_id = $request->[REQ_TIMER];
  if (delete $heap->{timer_to_request}->{$alarm_id}) {
    $kernel->alarm_remove( $alarm_id );
  }

  # If there was a non-zero error, then something bad happened.  Post
  # an error response back.
  if ($errnum) {
    $request->[REQ_POSTBACK]->
      ( HTTP::Response->new( 400, "$operation error $errnum: $errstr" )
      );
    return;
  }

  # Otherwise the remote end simply closed.  If we've built a
  # response, then post it back.
  if ($request->[REQ_STATE] & (RS_IN_CONTENT | RS_DONE)) {

    # If we have a cookie jar, have it frob our headers.  LWP rocks!
    if (defined $heap->{cookie_jar}) {
      $heap->{cookie_jar}->extract_cookies($request->[REQ_RESPONSE]);
    }

    $request->[REQ_POSTBACK]->($request->[REQ_RESPONSE]);
    return;
  }

  # We haven't built a proper response.  Send back an error.
  $request->[REQ_POSTBACK]->
    ( HTTP::Response->new( 400, "incomplete response" )
    );
}

#------------------------------------------------------------------------------
# Read a chunk of response.  This code is directly adapted from Artur
# Bergman's nifty POE::Filter::HTTPD, which does pretty much the same
# in the other direction.

sub poco_weeble_io_read {
  my ($kernel, $heap, $input, $wheel_id) = @_[KERNEL, HEAP, ARG0, ARG1];
  my $request_id = $heap->{wheel_to_request}->{$wheel_id};
  die unless defined $request_id;
  my $request = $heap->{request}->{$request_id};

  DEBUG and warn "wheel $wheel_id got input...\n";

  # Aggregate the new input.
  $request->[REQ_BUFFER] .= $input;

  # The very first line ought to be status.  If it's not, then it's
  # part of the content.
  if ($request->[REQ_STATE] & RS_IN_STATUS) {
    # Parse a status line. Detects the newline type, because it has to
    # or bad servers will break it.  What happens if someone puts
    # bogus headers in the content?
    if ( $request->[REQ_BUFFER] =~
         s/^(HTTP\/[0-9\.]+)?\s*(\d+)\s*(.*?)([\x0D\x0A]+)([^\x0D\x0A])/$5/
       ) {
      DEBUG and
        warn "wheel $wheel_id got a status line... moving to headers.\n";

      my $protocol;
      if (defined $1) {
        $protocol = $1;
      }
      else {
        $protocol= 'HTTP/0.9';
      }

      $request->[REQ_STATE]    = RS_IN_HEADERS;
      $request->[REQ_NEWLINE]  = $4;
      $request->[REQ_RESPONSE] = HTTP::Response->new( $2, $3 );
      $request->[REQ_RESPONSE]->protocol( $protocol );
      $request->[REQ_RESPONSE]->request( $request->[REQ_REQUEST] );
    }

    # No status line.  We go straight into content.  Since we don't
    # know the status, we don't purport to.
    else {
      DEBUG and warn "wheel $wheel_id got no status... moving to content.\n";
      $request->[REQ_RESPONSE] = HTTP::Response->new();
      $request->[REQ_STATE] = RS_IN_CONTENT;
    }
  }

  # Parse the input for headers.  This isn't in an else clause because
  # we may go from status to content in the same read.
  if ($request->[REQ_STATE] & RS_IN_HEADERS) {
    # Parse it by lines. -><- Assumes newlines are consistent with the
    # status line.  I just know this is too much to ask.
HEADER:
    while ( $request->[REQ_BUFFER] =~
            s/^(.*?)($request->[REQ_NEWLINE]|\x0D?\x0A)//
          ) {
      # This line means something.
      if (length $1) {
        my $line = $1;

        # New header.
        if ($line =~ /^([\w\-]+)\s*\:\s*(.+)\s*$/) {
          DEBUG and warn "wheel $wheel_id got a new header: $1 ...\n";

          $request->[REQ_LAST_HEADER] = $1;
          $request->[REQ_RESPONSE]->push_header($1, $2);
        }

        # Continued header.
        elsif ($line =~ /^\s+(.+?)\s*$/) {
          DEBUG and
            warn( "wheel $wheel_id got a continuation for header ",
                  $request->[REQ_LAST_HEADER],
                  " ...\n"
                );

          $request->[REQ_RESPONSE]->push_header
            ( $request->[REQ_LAST_HEADER], $1
            );
        }

        # Dunno what.
        else {
          # -><- bad request?
          DEBUG and warn "wheel $wheel_id got strange header line: <$line>";
        }
      }

      # This line is empty; we eat it and switch to RS_GET_CONTENT.
      else {
        DEBUG and
          warn "wheel $wheel_id got a blank line... moving to content.\n";

        $request->[REQ_STATE] = RS_IN_CONTENT;
        last HEADER;
      }
    }
  }

  # We're in a content state.  This isn't an else clause because we
  # may go from header to content in the same read.
  if ($request->[REQ_STATE] & RS_IN_CONTENT) {

    # Count how many octets we've received.
    my $this_chunk_length = length($request->[REQ_BUFFER]);
    $request->[REQ_OCTETS_GOT] += $this_chunk_length;

    # Add the new octets to the response's content.  -><- This should
    # only add up to content-length.
    $request->[REQ_RESPONSE]->add_content( $request->[REQ_BUFFER] );
    $request->[REQ_BUFFER] = '';

    DEBUG and do {
      warn "wheel $wheel_id got $this_chunk_length octets of content...\n";
      warn( "wheel $wheel_id has $request->[REQ_OCTETS_GOT]",
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

      my $progress = int( ($request->[REQ_OCTETS_GOT] * 100) /
                          $request->[REQ_RESPONSE]->content_length()
                        );

      $request->[REQ_PROG_POSTBACK]->
        ( $request->[REQ_OCTETS_GOT],
          $request->[REQ_RESPONSE]->content_length()
        ) if  $request->[REQ_PROG_POSTBACK];

      if ( $request->[REQ_OCTETS_GOT] >=
           $request->[REQ_RESPONSE]->content_length()
         )
      {
        DEBUG and
          warn "wheel $wheel_id has a full response... moving to done.\n";

        $request->[REQ_STATE] = RS_DONE;

        # -><- This assumes the server will now disconnect.  That will
        # give us an error 0 (socket's closed), and we will post the
        # response.
      }
    }
  }

  unless ($request->[REQ_STATE] & RS_DONE) {
    if ( defined($heap->{max_size}) and
         $request->[REQ_OCTETS_GOT] >= $heap->{max_size}
       ) {
      DEBUG and
        warn "wheel $wheel_id got enough data... moving to done.\n";

      if ( defined($request->[REQ_RESPONSE]) and
           defined($request->[REQ_RESPONSE]->code())
         ) {
        $request->[REQ_RESPONSE]->header
          ( 'X-Content-Range',
            'bytes 0-' . $request->[REQ_OCTETS_GOT] .
            ( $request->[REQ_RESPONSE]->content_length()
              ? ('/' . $request->[REQ_RESPONSE]->content_length())
              : ''
            )
          );
      }
      else {
        $request->[REQ_RESPONSE] =
          HTTP::Response->new( 400, "Response too large (and no headers)"
                             );
      }

      $request->[REQ_STATE] = RS_DONE;

      # Hang up on purpose.
      my $request_id = delete $heap->{wheel_to_request}->{$wheel_id};
      my $request = delete $heap->{request}->{$request_id};

      # Stop the timeout timer for this wheel, too.
      my $alarm_id = $request->[REQ_TIMER];
      if (delete $heap->{timer_to_request}->{$alarm_id}) {
        $kernel->alarm_remove( $alarm_id );
      }

      $request->[REQ_POSTBACK]->($request->[REQ_RESPONSE]);
    }
  }
}

1;

__END__

=head1 NAME

POE::Component::Client::HTTP - a HTTP user-agent component

=head1 SYNOPSIS

  use POE qw(Component::Client::HTTP);

  POE::Component::Client::HTTP->spawn(
    Agent    => 'SpiffCrawler/0.90',    # defaults to something long
    Alias    => 'ua',                   # defaults to 'weeble'
    From     => 'spiffster@perl.org',   # defaults to undef (no header)
    Protocol => 'HTTP/0.9',             # defaults to 'HTTP/1.0'
    Timeout  => 60,                     # defaults to 180 seconds
  );

  $kernel->post( 'ua',        # posts to the 'ua' alias
                 'request',   # posts to ua's 'request' state
                 'response',  # which of our states will receive the response
                 $request,    # an HTTP::Request object
               );

  # This is the sub which is called when the session receives a
  # 'response' event.
  sub response_handler {
    my ($request_packet, $response_packet) = @_[ARG0, ARG1];
    my $request_object  = $request_packet->[0];  # HTTP::Request
    my $response_object = $response_packet->[0]; # HTTP::Response

    print "*" x 78, "\n";
    print "*** my request:\n";
    print "-' x 78, "\n";
    print $request_object->as_string();
    print "*" x 78, "\n";

    print "*" x 78, "\n";
    print "*** their response:\n";
    print "-' x 78, "\n";
    print $response_object->as_string();
    print "*" x 78, "\n";
  }

=head1 DESCRIPTION

POE::Component::Client::HTTP is an HTTP user-agent for POE.  It lets
other sessions run while HTTP transactions are being processed, and it
lets several HTTP transactions be processed in parallel.

HTTP client components are not proper objects.  Instead of being
created, as most objects are, they are "spawned" as separate sessions.
To avoid confusion (and hopefully not cause other confusion), they
must be spawned with a C<spawn> method, not created anew with a C<new>
one.

PoCo::Client::HTTP's C<spawn> method takes a few named parameters:

=over 2

=item Agent => $user_agent_string

C<Agent> defines the string that identifies the component to other
servers.  $user_agent_string is "POE-Component-Client-HTTP/$VERSION",
by default.  You may want to change this to help identify your own
programs instead.

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

=item Protocol => $http_protocol_string

C<Protocol> advertises the protocol that the client wishes to see.
Under normal circumstances, it should be left to its default value:
"HTTP/1.0".

=item Timeout => $query_timeout

C<Timeout> specifies the amount of time a HTTP request will wait for
an answer.  This defaults to 180 seconds (three minutes).

=back

Sessions communicate asynchronously with PoCo::Client::HTTP.  They
post requests to it, and it posts responses back.

Requests are posted to the component's "request" state.  They include
an HTTP::Request object which defines the request.  For example:

  $kernel->post( 'ua', 'request',           # http session alias & state
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

The example progress handler shows how to calculate a percentage of
download completion.

  sub progress_handler {
    my $gen_args  = $_[ARG0];    # args passed to all calls
    my $call_args = $_[ARG1];    # args specific to the call

    my $req = $gen_args->[0];    # HTTP::Request object being serviced
    my $tag = $gen_args->[1];    # Request ID tag from.
    my $got = $call_args->[0];   # Bytes retrieved so far.
    my $tot = $call_args->[1];   # Total bytes to be retrieved.

    my $percent = $got / $tot * 100;

    printf( "-- %.0f%% [%d/%d]: %s\n",
            $percent, $got, $tot, $req->uri()
          );
  }

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
Timeout, Proxy, NoProxy.

=head1 AUTHOR & COPYRIGHTS

POE::Component::Client::HTTP is Copyright 1999-2000 by Rocco Caputo.
All rights are reserved.  POE::Component::Client::HTTP is free
software; you may redistribute it and/or modify it under the same
terms as Perl itself.

=cut
