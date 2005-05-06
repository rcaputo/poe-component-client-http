# $Id: HTTP.pm,v 1.56 2004/07/13 18:02:37 rcaputo Exp $
# License and documentation are after __END__.

package POE::Component::Client::HTTP::RequestFactory;
use strict;
use warnings;

use Carp;
use POE::Component::Client::HTTP::Request qw(:states :fields);

sub FCT_AGENT           () {  0 }
sub FCT_STREAMING       () {  1 }
sub FCT_MAXSIZE         () {  2 }
sub FCT_PROTOCOL        () {  3 }
sub FCT_COOKIEJAR       () {  4 }
sub FCT_FROM            () {  5 }
sub FCT_NOPROXY         () {  6 }
sub FCT_PROXY           () {  7 }
sub FCT_FOLLOWREDIRECTS () {  8 }

our $VERSION = "0.01";
sub DEBUG () { 0 }

sub DEFAULT_BLOCK_SIZE () { 4096 }

sub new {
  my ($class, $params) = @_;

  croak __PACKAGE__ . "expects its arguments in a hashref"
      unless (!defined ($params) or ref($params) eq 'HASH');

  # Accept an agent, or a reference to a list of agents.
  my $agent = delete $params->{Agent};
  $agent = [] unless defined $agent;
  if (ref($agent) eq "") {
    $agent = [ $agent ];
  }
  unless (ref($agent) eq "ARRAY") {
    croak "Agent must be a scalar or a reference to a list of agent strings";
  }

  push(
    @$agent,
    sprintf(
      'POE-Component-Client-HTTP/%s (perl; N; POE; en; rv:%f)',
      $VERSION, $VERSION
    )
  ) unless @$agent;

  my $max_size = delete $params->{MaxSize};

  my $streaming = delete $params->{Streaming};

  my $protocol = delete $params->{Protocol};
  $protocol = 'HTTP/1.1' unless defined $protocol and length $protocol;

  my $cookie_jar       = delete $params->{CookieJar};
  my $from             = delete $params->{From};
  my $no_proxy         = delete $params->{NoProxy};
  my $proxy            = delete $params->{Proxy};
  my $follow_redirects = delete $params->{FollowRedirects};

  # Process HTTP_PROXY and NO_PROXY environment variables.

  $proxy    = $ENV{HTTP_PROXY} || $ENV{http_proxy} unless defined $proxy;
  $no_proxy = $ENV{NO_PROXY}   || $ENV{no_proxy}   unless defined $no_proxy;

  # Translate environment variable formats into internal versions.

  if (defined $proxy) {
    if (ref($proxy) eq 'ARRAY') {
      croak "Proxy must contain [HOST,PORT]" unless @$proxy == 2;
      $proxy = [ $proxy ];
    }
    else {
      my @proxies = split /\s*\,\s*/, $proxy;
      foreach (@proxies) {
        s/^http:\/+//;
        s/\/+$//;
        croak "Proxy must contain host:port" unless /^(.+):(\d+)$/;
        $_ = [ $1, $2 ];
      }
      $proxy = \@proxies;
    }
  }

  if (defined $no_proxy) {
    unless (ref($no_proxy) eq 'ARRAY') {
      $no_proxy = [ split(/\s*\,\s*/, $no_proxy) ];
    }
  }

  my $self = [
    $agent,            # FCT_AGENT
    $streaming,        # FCT_STREAMING
    $max_size,         # FCT_MAXSIZE
    $protocol,         # FCT_PROTOCOL
    $cookie_jar,       # FCT_COOKIEJAR
    $from,             # FCT_FROM
    $no_proxy,         # FCT_NOPROXY
    $proxy,            # FCT_PROXY
    $follow_redirects, # FCT_FOLLOWREDIRECTS
  ];

  return bless $self, $class;
}

sub is_streaming {
  my ($self) = @_;

  DEBUG and warn "FCT: this is "
		. ($self->[FCT_STREAMING] ? "" : "not ")
		. "streaming";
  return $self->[FCT_STREAMING];
}

sub check_redirect {
  my ($self, $request) = @_;

  if ($self->[FCT_FOLLOWREDIRECTS]) { # redirect
    if ($request->does_redirect) {
	  
      # delete OLD timeout
      #my $alarm_id = $request->history->[0]->[REQ_TIMEOUT];
      #DEBUG and warn "RED: Removing old timeout $alarm_id\n";
      #$POE::Kernel::poe_kernel->alarm_remove ($alarm_id);
    }
  }
}

sub agent {
    my ($self) = @_;

    return $self->[FCT_AGENT]->[rand @{$self->[FCT_AGENT]}];
}

sub from {
  my ($self) = @_;

  if (defined $self->[FCT_FROM] and length $self->[FCT_FROM]) {
    return $self->[FCT_FROM];
  }
  return undef;
}

sub create_request {
  my ($self, $http_request, $response_event, $tag, $progress_event, $sender) = @_;

  # Add a protocol if one isn't included.
  $http_request->protocol( $self->[FCT_PROTOCOL] )
    unless (
      defined $http_request->protocol()
      and length $http_request->protocol()
    );


  # Add the User-Agent: header if one isn't included.
  unless (defined $http_request->user_agent()) {
    $http_request->user_agent($self->agent);
  }

  # Add a From: header if one isn't included.
  if (defined $self->from) {
    my $req_from = $http_request->from();
    unless (defined $req_from and length $req_from) {
      $http_request->from( $self->from );
    }
  }

  my ($last_request, $postback);
  if (ref($response_event)) {
    $last_request = $response_event;
    $postback = $last_request->postback;
  } else {
    $postback = $sender->postback( $response_event, $http_request, $tag );
  }
  # Create a progress postback if requested.
  my $progress_postback;
  if (defined $progress_event) {
    $progress_postback = $sender->postback($progress_event, $http_request, $tag);
  }

  # If we have a cookie jar, have it add the appropriate headers.
  # LWP rocks!

  if (defined $self->[FCT_COOKIEJAR]) {
    $self->[FCT_COOKIEJAR]->add_cookie_header($http_request);
  }

  # MEXNIX 2002-06-01: If we have a proxy set, and the request URI is
  # not in our no_proxy, then use the proxy.  Otherwise use the
  # request URI.

  my $proxy = $self->[FCT_PROXY];
  my $using_proxy;
  if (defined $proxy) {
  # This request qualifies for proxying.  Replace the host and port
  # with the proxy's host and port.  This comes after the Host:
  # header is set, so it doesn't break the request object.
    my $host = $http_request->uri->host;
    if (not _in_no_proxy ($host, $self->[FCT_NOPROXY])) {
      my $using_proxy = $proxy->[@$proxy];
    }
  }

  my $request = POE::Component::Client::HTTP::Request->new (
      Request => $http_request,
      Proxy => $using_proxy,
      Postback => $postback,
      Tag => $tag,
      Progress => $progress_postback,
    );

  if (defined $last_request) {
    $request->does_redirect ($last_request);
  }
  return $request;
}

# Determine whether a host is in a no-proxy list.
# {{{ _in_no_proxy

sub _in_no_proxy {
  my ($host, $no_proxy) = @_;
  foreach my $no_proxy_domain (@$no_proxy) {
    return 1 if $host =~ /\Q$no_proxy_domain\E$/i;
  }
  return 0;
}

# }}} _in_no_proxy

sub check_size_constraint {
  my ($self, $request) = @_;

  my $max = $self->[FCT_MAXSIZE];
  return unless (defined $max);

  DEBUG and warn "FCT: request ", $request->ID,
	      " received $request->[REQ_OCTETS_GOT] bytes; maximum is $max";

  if ($request->[REQ_OCTETS_GOT] > $max) {
    # We've gone over the maximum content size to return.  Chop it # back.
    my $over = $request->[REQ_OCTETS_GOT] - $max;
    $request->[REQ_OCTETS_GOT] -= $over;
    substr($request->[REQ_BUFFER], -$over) = "";
  }
}

sub block_size {
  my ($self) = @_;

  my $block_size = $self->[FCT_STREAMING] || DEFAULT_BLOCK_SIZE;
  $block_size = DEFAULT_BLOCK_SIZE if $block_size < 1;

  return $block_size;
}

sub frob_cookies {
  my ($self, $request) = @_;

  if (defined $self->[FCT_COOKIEJAR]) {
    $self->[FCT_COOKIEJAR] ->extract_cookies($request->[REQ_RESPONSE]);
  }
}

1;
