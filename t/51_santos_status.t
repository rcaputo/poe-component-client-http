# $Id$
# vim: filetype=perl

use strict;
use warnings;

use Test::More tests => 4;

use POE qw(
  Wheel::ReadWrite
  Driver::SysRW
  Filter::Line
  Filter::Stream
  Filter::HTTPHead
);

ok(defined $INC{"POE/Filter/HTTPHead.pm"}, "loaded");

use IO::Handle;
use IO::File;

autoflush STDOUT 1;
my $request_number = 8;

my $session = POE::Session->create(
  inline_states => {
    _start  => \&start,
    input   => \&input,
    error   => \&error,
    flushed => \&flushed,
  },
);

POE::Kernel->run();
exit;

sub start {
  my ($kernel, $heap) = @_[KERNEL, HEAP];

  sysseek(DATA, tell(DATA), 0);

  my $filter = POE::Filter::HTTPHead->new;

  my $wheel = POE::Wheel::ReadWrite->new(
    Handle      => \*DATA,
    Driver      => POE::Driver::SysRW->new(BlockSize => 1000),
    InputFilter => $filter,
    InputEvent  => 'input',
    ErrorEvent  => 'error',
  );
  $heap->{'wheel'} = $wheel;
}

sub input {
  my ($kernel, $heap, $data) = @_[KERNEL, HEAP, ARG0];

  if ($heap->{wheel}->get_input_filter->isa("POE::Filter::HTTPHead")) {
    ok($data->isa("HTTP::Response"), "header received");
    $heap->{wheel}->set_filter(POE::Filter::Line->new());
    return;
  }

  ok($data eq "Test Content.", "content received");
}

sub error {
  my $heap = $_[HEAP];
  my ($type, $errno, $errmsg, $id) = @_[ARG0..$#_];

  is($errno, 0, "got EOF");
  delete $heap->{wheel};
}

# Below is an HTTP response that consists solely of a status line and
# some content.

__DATA__
HTTP/1.0 200 OK

Test Content.
