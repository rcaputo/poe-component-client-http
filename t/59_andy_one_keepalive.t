# $Id$
# vim: filetype=perl

# Test case for reusing a single keep-alive connection using max_per_host = 1

use strict;

use Test::More tests => 2;
use POE qw(
    Component::Client::Keepalive
    Component::Client::HTTP
);
use HTTP::Request;

# poe.perl.org dns is failing right now
#my $test_url = 'http://poe.perl.org/misc/test.html';

# A small gif on my server that supports keep-alive
my $test_url = 'http://www.hybridized.org/static/images/xml.gif';

my $cm = POE::Component::Client::Keepalive->new(
    keep_alive    => 5,
    max_open      => 4,
    max_per_host  => 1,
    timeout       => 10,
);

POE::Component::Client::HTTP->spawn( 
    Alias             => 'ua',
    ConnectionManager => $cm,
);

POE::Session->create(
    inline_states => {
        _start       => \&_start,
        got_response => \&got_response,
    },
    heap => {
        reqid => 1,
    }
);

POE::Kernel->run;
exit 0;

sub _start {
    my ( $kernel, $heap ) = @_[ KERNEL, HEAP ];
    
    my $req = HTTP::Request->new( GET => $test_url );
    $req->header( Connection => 'keep-alive' );
    
    $kernel->post(
        ua => request => 'got_response', $req
    );
}

sub got_response {
    my ( $kernel, $heap, $reqp, $resp ) = @_[ KERNEL, HEAP, ARG0, ARG1 ];
    
    my $res = $resp->[0];
    
    is( $res->code, 200, 'Request ' . $heap->{reqid} . ' ok' );
    
    if ( $heap->{reqid}++ == 1 ) { 
        # Make a second request on the first connection
        
        my $req = HTTP::Request->new( GET => $test_url );
        $req->header( Connection => 'close' );

        $kernel->post(
            ua => request => 'got_response', $req
        );
    }
    else {    
        $kernel->post( ua => 'shutdown' );
    }
}
