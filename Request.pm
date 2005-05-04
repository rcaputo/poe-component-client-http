package POE::Component::Client::HTTP::Request;
use strict;
use warnings;

use POE;
use Carp;

# Unique request ID, independent of wheel and timer IDs.
my $request_seq = 0;

sub DEBUG () { 1 }

sub REQ_ID            () {  0 }
sub REQ_POSTBACK      () {  1 }
sub REQ_CONNECTION    () {  2 }
sub REQ_REQUEST       () {  3 }
sub REQ_STATE         () {  4 }
sub REQ_RESPONSE      () {  5 }
sub REQ_BUFFER        () {  6 }
sub REQ_LAST_HEADER   () {  7 }
sub REQ_OCTETS_GOT    () {  8 }
sub REQ_TIMER         () {  9 }
sub REQ_PROG_POSTBACK () { 10 }
sub REQ_USING_PROXY   () { 11 }
sub REQ_HOST          () { 12 }
sub REQ_PORT          () { 13 }
sub REQ_HISTORY       () { 14 }
sub REQ_START_TIME    () { 15 }
sub REQ_HEAD_PARSER   () { 16 }

sub RS_CONNECT      () { 0x01 }
sub RS_SENDING      () { 0x02 }
sub RS_IN_STATUS    () { 0x04 }
sub RS_IN_HEADERS   () { 0x08 } # not used anymore
sub RS_CHK_REDIRECT () { 0x10 } # not used anymore
sub RS_IN_CONTENT   () { 0x20 }
sub RS_DONE         () { 0x40 }
sub RS_POSTED       () { 0x80 }

sub import {
  my ($class) = shift;

  my $package = caller();

  foreach my $tag (@_) {
    if ($tag eq ':fields') {
      foreach my $sub (qw(
	REQ_ID REQ_POSTBACK REQ_CONNECTION REQ_REQUEST REQ_STATE REQ_RESPONSE
	REQ_BUFFER REQ_LAST_HEADER REQ_OCTETS_GOT REQ_TIMER REQ_PROG_POSTBACK
	REQ_USING_PROXY REQ_HOST REQ_PORT REQ_HISTORY REQ_START_TIME
	REQ_HEAD_PARSER
		    )) {
	no strict 'refs';
	*{$package . "::$sub"} = \&$sub;
      }
    }
    if ($tag eq ':states') {
      foreach my $sub (qw(
	RS_CONNECT RS_SENDING RS_IN_STATUS RS_IN_HEADERS RS_CHK_REDIRECT
	RS_IN_CONTENT RS_DONE RS_POSTED
		    )) {
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

  croak __PACKAGE__ . "expects its arguments to be key/value pairs"
    if (@_ & 1);
  my %params = @_;


  croak "need a Request parameter" unless (defined $params{'Request'});
  #croak "need a Tag parameter" unless (defined $params{'Tag'});

  my ($http_request, $postback, $tag, $progress) =
				    @params{qw(Request Postback Tag Progress)};

  my $request_id = ++$request_seq;
  DEBUG and warn "REQ: creating a request ($request_id)";

  # Get the host and port from the request object.
  my ($host, $port, $scheme, $using_proxy);

  eval {
    $host   = $http_request->uri()->host();
    $port   = $http_request->uri()->port();
    $scheme = $http_request->uri()->scheme();
  };
  if ($@) {
    warn $@;
    return;
  }

  # Add a host header if one isn't included.  Must do this before
  # we reset the $host for the proxy!
  _set_host_header ($http_request)
    unless (  defined $http_request->header('Host')
	and   length $http_request->header('Host')
      );


  if (defined $params{Proxy}) {
    # This request qualifies for proxying.  Replace the host and port
    # with the proxy's host and port.  This comes after the Host:
    # header is set, so it doesn't break the request object.
    ($host, $port) = $params{Proxy}->[rand @{$params{Proxy}}];
    $using_proxy = 1;
  } else {
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
    undef,              # REQ_LAST_HEADER
    0,                  # REQ_OCTETS_GOT
    undef,              # REQ_TIMER
#    "\x0D\x0A",         # REQ_NEWLINE
    $progress,          # REQ_PROG_POSTBACK
    $using_proxy,       # REQ_USING_PROXY
    $host,              # REQ_HOST
    $port,              # REQ_PORT
    undef,		# REQ_HISTORY
    time(),             # REQ_START_TIME
    undef,              # REQ_HEAD_PARSER
   ];
   return bless $self, $class;
}

sub create_timer {
  my ($self, $timeout) = @_;

  my $kernel = $POE::Kernel::poe_kernel;

  my $seconds = $timeout - (time() - $self->[REQ_START_TIME]);
  $self->[REQ_TIMER] =
      $kernel->delay_set (got_timeout =>
	  $seconds, $self->ID
	);
  DEBUG and warn "TKO: request ", $self->ID,
    " has timer $self->[REQ_TIMER] going off in $seconds seconds\n";
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
    # TODO - Should we check for SSL ports here?
    if ($new_port == 80) {
      $request->header( Host => $new_host );
    } else {
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
    $history = 10 if ($prev->[REQ_REQUEST]->uri eq $new_uri);
    last if ($history > 5);
  }

  if ($history > 5) {
    $self->[REQ_STATE] = RS_DONE;
    DEBUG and warn "RED: Too much redirection, moving to done\n";
  } else { # All fine, yield new request and mark this disabled.
    my $newrequest = $self->[REQ_REQUEST]->clone();
    DEBUG and warn "RED: new request $newrequest";
    $newrequest->uri($new_uri);
    _set_host_header ($newrequest);

    #$POE::Kernel::poe_kernel->yield(
	  #request => $self,
	  #$newrequest, "_redir_".$self->ID,
	  #$self->[REQ_PROG_POSTBACK]
	  #);
    #$heap->{redir}->{$request_id}->{request} = $request->[REQ_REQUEST];
    #$heap->{redir}->{$request_id}->{followed} = 1; # Mark redirected.

    DEBUG and warn "RED: Complete the redirect";
    #if (K) {
	## _remove_timeout($kernel, $heap, $request);
	## _finish_redirect($heap, $request_id, $request);
	#$heap->{redir}->{$request_id}->{timeout} = $request->[REQ_TIMER];

	## _finish_request($heap, $request_id, $request);
      $self->[REQ_STATE] = RS_DONE | RS_POSTED;
    #}
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
  use HTTP::Status;
  my $http_msg = status_message ($code);
  my $m = "<html>$nl"
      .	  "<HEAD><TITLE>Error: $http_msg</TITLE></HEAD>$nl"
      .	  "<BODY>$nl"
      .	  "<H1>Error: $http_msg</H1>$nl"
      .	  "$message$nl"
      .	  "</BODY>$nl"
      .	  "</HTML>$nl";

  $r->content ($m);
  $self->[REQ_POSTBACK]->($r);
}

sub connect_error {
  my ($self, $message) = @_;

  my $nl = "\n";

  my $host = $self->[REQ_HOST];
  my $port = $self->[REQ_PORT];

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

  $self->[REQ_POSTBACK]->($response);
  return;
}

sub DESTROY {
  my ($self) = @_;

  delete $self->[REQ_CONNECTION];
}

1;

