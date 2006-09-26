#!perl
# simple test case to exhibit behaviour where PoCoClHTTP fails when cancelling
# a request before connection pool connections have been established

use strict;
use warnings;
use HTTP::Request;
use HTTP::Status;
use Test::More tests => 16;

use constant DEBUG => 0;

sub POE::Kernel::TRACE_EVENTS     () { 0 }
sub POE::Kernel::TRACE_REFCNT     () { 0 }
sub POE::Kernel::CATCH_EXCEPTIONS () { 0 }
use POE qw(Component::Client::HTTP);

POE::Component::Client::HTTP->spawn( Alias => 'ua' );

POE::Session->create(
  inline_states => {
    _start   => \&client_start,
    response => \&response_handler
  }
);

our %responses;
eval { POE::Kernel->run(); };
ok (!$@, "cancelling req before connection succeeds does not die");
diag($@) if $@;
is (scalar keys %responses, 2, "got 2 HTTP responses");
ok (exists $responses{'http://poe.perl.org/'}, "got response from poe.perl.org");
ok (exists $responses{'http://www.google.com/'}, "got response from poe.perl.org");

my $poe = $responses{'http://poe.perl.org/'};
is (scalar @{ $poe }, 1, "1 response for poe.perl.org");
ok ( $poe->[0]->is_success, "successful request to poe.perl.org" );

my $google = $responses{'http://www.google.com/'};
is (scalar @{ $google }, 2, "2 responses for www.google.com");
my ($ok, $timeout) = 0;
for (@{ $google }) {
  my $code = $_->code;
  if ($code == RC_OK || $code == RC_FOUND) {
    $ok++;
  } elsif ($code == RC_REQUEST_TIMEOUT) {
    $timeout++;
  } else {
    warn "unexpected status code $code";
  }
}

is( $ok,      1, "got one successful response from google.com" );
is( $timeout, 1, "got one timed-out response from google.com" );

exit;

sub client_start{
  my $request = HTTP::Request->new('GET', "http://www.google.com/");
  ok(
	$_[KERNEL]->post( ua => request => response => $request ),
	"post 1st req succeeds"
  );

  my $req2 = HTTP::Request->new('GET', "http://www.google.com/");
  ok(
    $_[KERNEL]->post( ua => request => response => $req2 ),
	"post 2nd req succeeds"
  );

  my $req3 = HTTP::Request->new('GET', "http://poe.perl.org/");
  ok (
    $_[KERNEL]->post( ua => request => response => $req3 ),
	"post 3rd req succeeds"
  );
	

  ok( $_[KERNEL]->post( ua => cancel => $request ), "cancel 1st req succeeds" );

}


sub response_handler {
  my $response = $_[ARG1][0];
  ok(defined $response, "got a " . $response->code . " HTTP response");
  if (DEBUG) {
    print $response->as_string();
    print "\n\n", $response->server, "\n\n";
  }
  my $base = $response->base->as_string;
  if (exists $responses{$base}) {
    push @{$responses{$base}}, $response;
  } else {
    $responses{$base} = [ $response ];
  }
}
