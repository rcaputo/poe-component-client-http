# $Id$
# vim: filetype=perl

use strict;
use warnings;

use Test::More tests => 8;

use POE qw(
  Wheel::ReadWrite
  Driver::SysRW
  Filter::Line
  Filter::Stream
  Filter::HTTPHead
  Filter::XML
);

ok(defined $INC{"POE/Filter/HTTPHead.pm"}, "loaded");

use IO::Handle;
use IO::File;

autoflush STDOUT 1;
my $request_number = 8;

my $session = POE::Session->create(
  inline_states => {
    _start => \&start,
    input => \&input,
    error => \&error,
    flushed => \&flushed,
  },
);

POE::Kernel->run();
exit;

sub start {
  my ($kernel, $heap) = @_[KERNEL, HEAP];

  sysseek(DATA, tell(DATA), 0);

  my $filter = POE::Filter::HTTPHead->new;

  my $wheel = POE::Wheel::ReadWrite->new (
    Handle => \*DATA,
    Driver => POE::Driver::SysRW->new (BlockSize => 1000),
    InputFilter => $filter,
    InputEvent => 'input',
    ErrorEvent => 'error',
  );
  $heap->{'wheel'} = $wheel;
}

sub input {
  my ($kernel, $heap, $data) = @_[KERNEL, HEAP, ARG0];
  if ($heap->{wheel}->get_input_filter->isa('POE::Filter::Line')) {
    $request_number == 2 and is($data, 'content', "Got content foo");
    #$request_number == 1 and is($data, 'contents', "Got content bar");
    $heap->{wheel}->set_input_filter(POE::Filter::HTTPHead->new);
  }
  $request_number--;

  $request_number == 7 and isa_ok($data, 'HTTP::Response', "Ok sans headers");
  $request_number == 6 and isa_ok($data, 'HTTP::Response', "Got our object");
  $request_number == 5 and ok(!defined($data), "Got a bad request");
  $request_number == 4 and ok(
    !defined($data->header('Connection')),
    "Not picking up bad request headers"
  );
  $request_number == 3 and isa_ok($data, 'HTTP::Response', "No HTTP version");
  if ($request_number <= 2) {
    $heap->{wheel}->set_filter(POE::Filter::Line->new());
  }
}

sub error {
  my $heap = $_[HEAP];
  my ($type, $errno, $errmsg, $id) = @_[ARG0..$#_];

  is($errno, 0, "got EOF");
  delete $heap->{wheel};
}

# below is a list of the heads of HTTP responses (i.e with no content)
# these are used to drive the tests.
# Note that the last one does have a line of content, so we get more
# coverage because we switch filters for it
# If you want to add a head to test, put it as the first one,
# and add a $response_number == n and ok(1, foo) statement to the
# input subroutine n should be the number $response_number gets
# initialized to right now. Then increase the initialization and
# the number of tests planned.

__DATA__
HTTP/1.1 202 Accepted

HTTP/1.1 200 Ok
Date: Mon, 08 Nov 2004 21:37:20 GMT
Server: Apache/2.0.50 (Debian GNU/Linux) DAV/2 SVN/1.0.1-dev mod_ssl/2.0.50 OpenSSL/0.9.7d
Last-Modified: Sat, 24 Nov 2001 16:48:12 GMT
ETag: "6e-100e-18d96b00"
Accept-Ranges: bytes
Content-Length: 4110
Connection: close
Content-Type: text/html;
        charset=ISO-8859-1

garble
HTTP/1.1 200 Ok
Date: Mon, 08 Nov 2004 21:37:20 GMT
Server: Apache/2.0.50 (Debian GNU/Linux) DAV/2 SVN/1.0.1-dev mod_ssl/2.0.50 OpenSSL/0.9.7d
Last-Modified: Sat, 24 Nov 2001 16:48:12 GMT
ETag: "6e-100e-18d96b00"
Accept-Ranges: bytes
Content-Length: 4110
Connection close
Content-Type: text/html;
        charset=ISO-8859-1

200 Ok
Date: Mon, 08 Nov 2004 21:37:20 GMT
Server: Apache/2.0.50 (Debian GNU/Linux) DAV/2 SVN/1.0.1-dev mod_ssl/2.0.50 OpenSSL/0.9.7d
Last-Modified: Sat, 24 Nov 2001 16:48:12 GMT
ETag: "6e-100e-18d96b00"
Accept-Ranges: bytes
Content-Length: 4110
Connection: close
Content-Type: text/html;
        charset=ISO-8859-1

HTTP/1.1 200 Ok
Date: Mon, 08 Nov 2004 21:37:20 GMT
Server: Apache/2.0.50 (Debian GNU/Linux) DAV/2 SVN/1.0.1-dev mod_ssl/2.0.50 OpenSSL/0.9.7d
Last-Modified: Sat, 24 Nov 2001 16:48:12 GMT
ETag: "6e-100e-18d96b00"
Accept-Ranges: bytes
Content-Length: 4110
Connection: close
Content-Type: text/html;
        charset=ISO-8859-1

content
