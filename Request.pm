# $Id$

package POE::Component::Client::HTTP::Request;
use strict;
use warnings;

use POE;

use Carp;
use HTTP::Status;

# Unique request ID, independent of wheel and timer IDs.
my $request_seq = 0;

sub DEBUG () { 0 }

sub REQ_ID            () {  0 }
sub REQ_POSTBACK      () {  1 }
sub REQ_CONNECTION    () {  2 }
sub REQ_REQUEST       () {  3 }
sub REQ_STATE         () {  4 }
sub REQ_RESPONSE      () {  5 }
sub REQ_BUFFER        () {  6 }

sub REQ_OCTETS_GOT    () {  8 }
sub REQ_TIMER         () {  9 }
sub REQ_PROG_POSTBACK () { 10 }
sub REQ_USING_PROXY   () { 11 }
sub REQ_HOST          () { 12 }
sub REQ_PORT          () { 13 }
sub REQ_HISTORY       () { 14 }
sub REQ_START_TIME    () { 15 }
sub REQ_FACTORY       () { 16 }

sub RS_CONNECT      () { 0x01 }
sub RS_SENDING      () { 0x02 }
sub RS_IN_HEAD      () { 0x04 }
sub RS_REDIRECTED   () { 0x08 }
sub RS_IN_CONTENT   () { 0x20 }
sub RS_DONE         () { 0x40 }
sub RS_POSTED       () { 0x80 }

sub import {
  my ($class) = shift;

  my $package = caller();

  foreach my $tag (@_) {
    if ($tag eq ':fields') {
      foreach my $sub (
        qw(
          REQ_ID REQ_POSTBACK REQ_CONNECTION REQ_REQUEST REQ_STATE
          REQ_RESPONSE REQ_BUFFER REQ_OCTETS_GOT REQ_TIMER
          REQ_PROG_POSTBACK REQ_USING_PROXY REQ_HOST REQ_PORT
          REQ_HISTORY REQ_START_TIME
        )
      ) {
        no strict 'refs';
        *{$package . "::$sub"} = \&$sub;
      }
    }

    if ($tag eq ':states') {
      foreach my $sub (
        qw(
          RS_CONNECT RS_SENDING RS_IN_HEAD RS_REDIRECTED
          RS_IN_CONTENT RS_DONE RS_POSTED
        )
      ) {
        no strict 'refs';
        *{$package . "::$sub"} = \&$sub;
      }
    }
  }
}

sub ID {
  my ($self) = @_;
  return $self->[REQ_ID];
}

sub new {
  my $class = shift;

  croak __PACKAGE__ . "expects its arguments to be key/value pairs" if @_ & 1;
  my %params = @_;

  croak "need a Request parameter" unless (defined $params{'Request'});
  croak "Request must be a HTTP::Request object"
    unless (UNIVERSAL::isa ($params{'Request'}, "HTTP::Request"));

  #croak "need a Tag parameter" unless (defined $params{'Tag'});

  croak "need a Factory parameter" unless (defined $params{'Factory'});

  my ($http_request, $postback, $tag, $progress, $factory) =
    @params{qw(Request Postback Tag Progress Factory)};

  my $request_id = ++$request_seq;
  DEBUG and warn "REQ: creating a request ($request_id)";

  # Get the host and port from the request object.
  my ($host, $port, $scheme, $using_proxy);

  eval {
    $host   = $http_request->uri()->host();
    $port   = $http_request->uri()->port();
    $scheme = $http_request->uri()->scheme();
  };
  croak "Not a usable Request: $@" if ($@);

  # Add a host header if one isn't included.  Must do this before
  # we reset the $host for the proxy!
  _set_host_header ($http_request) unless (
    defined $http_request->header('Host') and
    length $http_request->header('Host')
  );


  if (defined $params{Proxy}) {
    # This request qualifies for proxying.  Replace the host and port
    # with the proxy's host and port.  This comes after the Host:
    # header is set, so it doesn't break the request object.
    ($host, $port) = $params{Proxy}->[rand @{$params{Proxy}}];
    $using_proxy = 1;
  }
  else {
    $using_proxy = 0;
  }

  # Build the request.
  my $self = [
    $request_id,        # REQ_ID
    $postback,          # REQ_POSTBACK
    undef,              # REQ_CONNECTION
    $http_request,      # REQ_REQUEST
    RS_CONNECT,         # REQ_STATE
    undef,              # REQ_RESPONSE
    '',                 # REQ_BUFFER
    undef,              # unused
    0,                  # REQ_OCTETS_GOT
    undef,              # REQ_TIMER
    $progress,          # REQ_PROG_POSTBACK
    $using_proxy,       # REQ_USING_PROXY
    $host,              # REQ_HOST
    $port,              # REQ_PORT
    undef,              # REQ_HISTORY
    time(),             # REQ_START_TIME
    $factory,           # REQ_FACTORY
   ];
   return bless $self, $class;
}

sub return_response {
  my ($self) = @_;

  DEBUG and warn "in return_response ", sprintf ("0x%02X", $self->[REQ_STATE]);
  return if ($self->[REQ_STATE] & RS_POSTED);
  my $response = $self->[REQ_RESPONSE];

  # If we have a cookie jar, have it frob our headers.  LWP rocks!
  $self->[REQ_FACTORY]->frob_cookies ($response);

  # If we're done, send back the HTTP::Response object, which
  # is filled with content if we aren't streaming, or empty
  # if we are. that there's no ARG1 lets the client know we're done
  # with the content in the latter case
  if ($self->[REQ_STATE] & RS_DONE) {
    DEBUG and warn "done; returning $response for ", $self->[REQ_ID];
    $self->[REQ_POSTBACK]->($self->[REQ_RESPONSE]);
    $self->[REQ_STATE] |= RS_POSTED;
    #warn "state is now ", $self->[REQ_STATE];
  }
  elsif ($self->[REQ_STATE] & RS_IN_CONTENT) {
    # If we are streaming, send the chunk back to the client session.
    # Otherwise add the new octets to the response's content.
    # This should only add up to content-length octets total!
    if ($self->[REQ_FACTORY]->is_streaming) {
      DEBUG and warn "returning partial $response";
      $self->[REQ_POSTBACK]->($self->[REQ_RESPONSE], $self->[REQ_BUFFER]);
    }
    else {
      DEBUG and warn "adding to $response";
      $self->[REQ_RESPONSE]->add_content($self->[REQ_BUFFER]);
    }
  }
  $self->[REQ_BUFFER] = '';
}

sub add_eof {
  my ($self) = @_;

  return if ($self->[REQ_STATE] & RS_POSTED);

  unless (defined $self->[REQ_RESPONSE]) {
    # XXX I don't know if this is actually used
    $self->error(400, "incomplete response " . $self->[REQ_ID]);
    return;
  }

  # RFC 2616: "If a message is received with both a Transfer-Encoding
  # header field and a Content-Length header field, the latter MUST be
  # ignored."
  if (
    defined $self->[REQ_RESPONSE]->content_length and
    not defined $self->[REQ_RESPONSE]->header("Transfer-Encoding") and
    $self->[REQ_OCTETS_GOT] < $self->[REQ_RESPONSE]->content_length
  ) {
    DEBUG and warn(
      "got " . $self->[REQ_OCTETS_GOT] . " of " .
      $self->[REQ_RESPONSE]->content_length
    );
    $self->error(400, "incomplete response " . $self->[REQ_ID]);
  }
  else {
    $self->[REQ_STATE] |= RS_DONE;
    $self->return_response();
  }
}

sub add_content {
  my ($self, $data) = @_;

  if (ref $data) {
    $self->[REQ_STATE] = RS_DONE;
    $data->scan (sub {$self->[REQ_RESPONSE]->header (@_) });
    return 1;
  }

  $self->[REQ_BUFFER] .= $data;

  # Count how many octets we've received.  -><- This may fail on
  # perl 5.8 if the input has been identified as Unicode.  Then
  # again, the C<use bytes> in Driver::SysRW may have untainted the
  # data... or it may have just changed the semantics of length()
  # therein.  If it's done the former, then we're safe.  Otherwise
  # we also need to C<use bytes>.
  # TODO: write test(s) for this.
  my $this_chunk_length = length($self->[REQ_BUFFER]);
  $self->[REQ_OCTETS_GOT] += $this_chunk_length;

  my $max = $self->[REQ_FACTORY]->max_response_size;

  DEBUG and warn(
    "REQ: request ", $self->ID,
    " received $self->[REQ_OCTETS_GOT] bytes; maximum is $max"
  );

  if (defined $max and $self->[REQ_OCTETS_GOT] > $max) {
    # We've gone over the maximum content size to return.  Chop it # back.
    my $over = $self->[REQ_OCTETS_GOT] - $max;
    $self->[REQ_OCTETS_GOT] -= $over;
    substr($self->[REQ_BUFFER], -$over) = "";
    #TODO: ??
    #$self->[REQ_STATE] |= RS_DONE;
  }

  # keep this for the progress callback (it gets cleared in return_response
  # as I say below, this needs to go away.
  my $buffer = $self->[REQ_BUFFER];

  $self->return_response;
  DEBUG and do {
    warn(
      "REQ: request ", $self->ID,
      " got $this_chunk_length octets of content..."
    );

    warn(
      "REQ: request ", $self->ID, " has $self->[REQ_OCTETS_GOT]",
      (
        $self->[REQ_RESPONSE]->content_length()
        ? ( " out of " . $self->[REQ_RESPONSE]->content_length() )
        : ""
      ),
      " octets"
    );
  };

  if (defined $max and $self->[REQ_OCTETS_GOT] >= $max) {
    DEBUG and warn(
      "REQ: request ", $self->ID, " has a full response... moving to done."
    );
    $self->[REQ_STATE] |= RS_DONE;
    $self->[REQ_STATE] &= ~RS_IN_CONTENT;
    return 1;
  }

  if ($self->[REQ_RESPONSE]->content_length) {

    # Report back progress
    $self->[REQ_PROG_POSTBACK]->(
      $self->[REQ_OCTETS_GOT],
      $self->[REQ_RESPONSE]->content_length,
      #TODO: ugh. this is stupid. Must remove/deprecate!
      $buffer,
    ) if ($self->[REQ_PROG_POSTBACK]);

    # Stop reading when we have enough content.  -><- Should never be
    # greater than our content length.
    if ($self->[REQ_OCTETS_GOT] >= $self->[REQ_RESPONSE]->content_length) {
      DEBUG and warn(
        "REQ: request ", $self->ID, " has a full response... moving to done."
      );
      $self->[REQ_STATE] |= RS_DONE;
      $self->[REQ_STATE] &= ~RS_IN_CONTENT;
      return 1;
    }
  }
  return 0;
}

sub timer {
  my ($self, $timer) = @_;

  # do it this way so we can set REQ_TIMER to undef
  if (@_ == 2) {
    die "overwriting timer $self->[REQ_TIMER]" if $self->[REQ_TIMER];
    $self->[REQ_TIMER] = $timer;
  }
  return $self->[REQ_TIMER];
}

sub create_timer {
  my ($self, $timeout) = @_;

  # remove old timeout first
  my $kernel = $POE::Kernel::poe_kernel;

  my $seconds = $timeout - (time() - $self->[REQ_START_TIME]);
  $self->[REQ_TIMER] = $kernel->delay_set(
    got_timeout => $seconds, $self->ID
  );
  DEBUG and warn(
    "TKO: request ", $self->ID,
    " has timer $self->[REQ_TIMER] going off in $seconds seconds\n"
  );
}

sub remove_timeout {
  my ($self) = @_;

  my $alarm_id = $self->[REQ_TIMER];
  if (defined $alarm_id) {
    my $kernel = $POE::Kernel::poe_kernel;
    DEBUG and warn "REQ: Removing timer $alarm_id";
    $kernel->alarm_remove($alarm_id);
    $self->[REQ_TIMER] = undef;
  }
}

sub postback {
  my ($self, $postback) = @_;

  if (defined $postback) {
    DEBUG and warn "REQ: modifying postback";
    $self->[REQ_POSTBACK] = $postback;
  }
  return $self->[REQ_POSTBACK];
}

sub _set_host_header {
  my ($request) = @_;
  my $uri = $request->uri;

  my ($new_host, $new_port);
  eval {
    $new_host = $uri->host();
    $new_port = $uri->port();
    # Only include the port if it's nonstandard.
    if ($new_port == 80 || $new_port == 443) {
      $request->header( Host => $new_host );
    }
    else {
      $request->header( Host => "$new_host:$new_port" );
    }
  };
  warn $@ if $@;
}

sub does_redirect {
  my ($self, $last) = @_;

  if (defined $last) {
    $self->[REQ_HISTORY] = $last;
    # delete OLD timeout
    #my $alarm_id = $last->[REQ_TIMEOUT];
    #DEBUG and warn "RED: Removing old timeout $alarm_id\n";
    #$POE::Kernel::poe_kernel->alarm_remove ($alarm_id);
  }

  return defined $self->[REQ_HISTORY];
}

sub check_redirect {
  my ($self) = @_;

  my $max = $self->[REQ_FACTORY]->max_redirect_count;

  if (defined $self->[REQ_HISTORY]) {
    $self->[REQ_RESPONSE]->previous($self->[REQ_HISTORY]->[REQ_RESPONSE]);
  }

  return undef unless ($self->[REQ_RESPONSE]->is_redirect);

  my $new_uri = $self->[REQ_RESPONSE]->header ('Location');
  DEBUG and warn "REQ: Preparing redirect to $new_uri";
  my $base = $self->[REQ_RESPONSE]->base();
  $new_uri = URI->new($new_uri, $base)->abs($base);
  DEBUG and warn "RED: Actual redirect uri is $new_uri";

  my $prev = $self;
  my $history = 0;
  while ($prev = $prev->[REQ_HISTORY]) {
    $history++;
    $history = $max + 1 if ($prev->[REQ_REQUEST]->uri eq $new_uri);
    last if ($history > $max);
  }

  if ($history > $max) {
    #$self->[REQ_STATE] |= RS_DONE;
    DEBUG and warn "RED: Too much redirection";
  }
  else { # All fine, yield new request and mark this disabled.
    my $newrequest = $self->[REQ_REQUEST]->clone();
    DEBUG and warn "RED: new request $newrequest";
    $newrequest->uri($new_uri);
    _set_host_header ($newrequest);

    $self->[REQ_STATE] = RS_REDIRECTED;
    DEBUG and warn "RED: new request $newrequest";
    return $newrequest;
  }
  return undef;
}

sub send_to_wheel {
  my ($self) = @_;

  $self->[REQ_STATE] = RS_SENDING;

  my $http_request = $self->[REQ_REQUEST];

  # MEXNIX 2002-06-01: Check for proxy.  Request query is a bit
  # different...

  my $request_uri;
  if ($self->[REQ_USING_PROXY]) {
    $request_uri = $http_request->uri()->canonical();
  }
  else {
    $request_uri = $http_request->uri()->canonical()->path_query();
  }

  my $request_string = (
    $http_request->method() . ' ' .
    $request_uri . ' ' .
    $http_request->protocol() . "\x0D\x0A" .
    $http_request->headers_as_string("\x0D\x0A") . "\x0D\x0A" .
    $http_request->content() # . "\x0D\x0A"
  );

  DEBUG and do {
    my $formatted_request_string = $request_string;
    $formatted_request_string =~ s/([^\n])$/$1\n/;
    $formatted_request_string =~ s/^/| /mg;
    warn ",----- SENDING REQUEST ", '-' x 56, "\n";
    warn $formatted_request_string;
    warn "`", '-' x 78, "\n";
  };

  $self->[REQ_CONNECTION]->wheel->put ($request_string);
}

sub wheel {
  my ($self) = @_;

  #if (defined $new_wheel) {
    # Switch wheels.  This is cumbersome, but it works around a bug in
    # older versions of POE.
    #$self->[REQ_WHEEL] = undef;
    #$self->[REQ_WHEEL] = $new_wheel;
  #}
  return $self->[REQ_CONNECTION]->wheel;
}

sub error {
  my ($self, $code, $message) = @_;

  my $nl = "\n";

  my $r = HTTP::Response->new($code);
  my $http_msg = status_message ($code);
  my $m = (
    "<html>$nl"
    . "<HEAD><TITLE>Error: $http_msg</TITLE></HEAD>$nl"
    . "<BODY>$nl"
    . "<H1>Error: $http_msg</H1>$nl"
    . "$message$nl"
    . "</BODY>$nl"
    . "</HTML>$nl"
  );

  $r->content ($m);
  $self->[REQ_POSTBACK]->($r);
}

sub connect_error {
  my ($self, $message) = @_;

  my $host = $self->[REQ_HOST];
  my $port = $self->[REQ_PORT];

  $message = "Cannon connect to $host:$port ($message)";
  $self->error (RC_INTERNAL_SERVER_ERROR, $message);
  return;
}

sub DESTROY {
  my ($self) = @_;

  delete $self->[REQ_CONNECTION];
  delete $self->[REQ_FACTORY];
}

1;
