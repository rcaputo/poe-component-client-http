# $Id$
# vim: filetype=perl

use strict;

use HTTP::Request::Common qw(GET POST);

sub POE::Kernel::ASSERT_DEFAULT () { 1 }
use POE qw(Component::Client::HTTP Component::Client::Keepalive);

sub DEBUG () { 0 }

sub MAX_BIG_REQUEST_SIZE  () { 4096 }
sub MAX_STREAM_CHUNK_SIZE () { 1024 }  # Needed for agreement with test CGI.

my $cm;
$| = 1;

my @test_results = (
  'not ok 1', 'not ok 2', 'not ok 3', 'not ok 4', 'not ok 5',
  'not ok 6', 'not ok 7', 'not ok 8', # 'not ok 9',
);

print "1..", scalar @test_results, "\n";

sub client_start {
  my ($kernel, $heap) = @_[KERNEL, HEAP];

  DEBUG and warn "client starting...\n";

  $kernel->post( weeble => request => got_first_response =>
    #GET 'http://poe.perl.org/misc/test.html'
    GET(
      'http://devel.exitexchange.com/~rob/test.html',
      Connection => "Keep-Alive",
    ),
  );

  $heap->{ka_count} = 5;

  $kernel->post(
    chunk => request => got_response =>
    # GET 'http://poe.perl.org/misc/test.html'

    # one packet, multiple chunks
    # GET 'http://www.searchrequest.net/'

    # BIG chunked response
    # GET 'http://www.dack.com/'

    # CHUNKED WITH REDIRECT
    GET(
      'http://www.overture.com/',
      Connection => 'close',
    ),

    # CHUNKED W/O REDIRECT
    # GET('http://www.content.overture.com/d/', Connection => 'close')

    # ONLY redirect
    # GET 'http://devel.exitexchange.com/scripts/poe_redir'
  );

  #$kernel->yield('check_counts', 2, 2);
}

sub client_check_counts {
  my ($kernel, $test_number, $expected_count) = @_[KERNEL, ARG0, ARG1];

  # a better test would be to also keep track of the responses we are
  # receiving and checking that pending_requests_count decrements properly.
  my $count = $kernel->call( weeble => 'pending_requests_count' );
  $test_results[$test_number-1] = "ok $test_number"
    if $expected_count == $count;
}

sub client_stop {
  DEBUG and warn "client stopped...\n";
  foreach (@test_results) {
    print "$_\n";
  }
  $cm->shutdown;
  $cm = undef;
}

sub client_got_first_response {
  my ($heap, $kernel, $request_packet, $response_packet) = @_[
    HEAP, KERNEL, ARG0, ARG1
  ];
  my $http_request  = $request_packet->[0];
  my $http_response = $response_packet->[0];

  # DEBUG and "client FIRST_RESPONSE: START";

  DEBUG and do {
    warn "client got request...\n";

    my $response_string = $http_response->as_string();
    $response_string =~ s/^/| /mg;

    warn ",", '-' x 78, "\n";
    warn $response_string;
    warn "`", '-' x 78, "\n";
  };

  my $request_path = $http_request->uri->path . ''; # stringify

  if (defined $http_response->code) {
    my $response_string = $http_response->as_string();
    if ($http_response->code == 200) {
      $test_results[0] = 'ok 1' if $request_path =~ m/\/test\.html$/;

      $kernel->post(
        weeble => request => got_response =>
        GET(
          'http://devel.exitexchange.com/~rob/test1.html',
          Connection => "Keep-Alive",
        ),
      ) if $request_path =~ /\/test\.html$/ and $heap->{ka_count}--;
    }
  }

  # DEBUG and "client FIRST_RESPONSE: DONE";
}

sub client_got_response {
  my ($heap, $kernel, $request_packet, $response_packet) = @_[
    HEAP, KERNEL, ARG0, ARG1
  ];
  my $http_request  = $request_packet->[0];
  my $http_response = $response_packet->[0];

  # DEBUG and "client SECOND_RESPONSE: START";

  DEBUG and do {
    warn "client got request...\n";

    my $response_string = $http_response->as_string();
    $response_string =~ s/^/| /mg;

    warn ",", '-' x 78, "\n";
    warn $response_string;
    warn "`", '-' x 78, "\n";
  };

  my $request_path = $http_request->uri->path . ''; # stringify
  my $request_uri  = $http_request->uri       . ''; # stringify

  if (defined $http_response->code) {
    my $response_string = $http_response->as_string();
    if ($http_response->code == 200) {
      $test_results[0] = 'ok 1' if $request_path =~ m/\/test\.html$/;

      $kernel->post(
        weeble => request => got_response =>
        GET(
          'http://devel.exitexchange.com/~rob/test2.html',
          Connection => "Keep-Alive",
        ),
      ) if $request_path =~ /\/test1\.html$/ and $heap->{ka_count}--;

      $test_results[1] = 'ok 2' if $response_string =~ /TEST1/;

      if ($response_string =~ /TEST2/) {
        $test_results[2] = 'ok 3';
        $kernel->post(
          weeble => request => got_response =>
          GET('http://devel.exitexchange.com/~rob/test3.html'),
        ) if $heap->{ka_count}--;
      }

      if ($response_string =~ /TEST3/) {
        $test_results[3] = 'ok 4';
        $kernel->post(
          weeble => request => got_response =>
          GET(
            'http://devel.exitexchange.com/~rob/test4.html',
            Connection => "Close"
          ),
        );
      }

      if ($response_string =~ /TEST4/) {
        $test_results[4] = 'ok 5';
        $kernel->post( chunk => request => got_response =>
          GET(
            'http://exit-val.looksmart.com/r_search?isp=exi&key=dogs',
            Connection => 'close',
          ),
        );
      }

      if ($request_uri =~ /=dogs$/) {
        $test_results[5] = 'ok 6';
        $kernel->post( chunk => request => got_response =>
          # GET 'http://poe.perl.org/misc/test.html'
          # GET 'http://www.searchrequest.net/'
          # GET 'http://www.dack.com/'
          GET(
            'http://exit-val.looksmart.com/r_search?isp=exi&key=cats',
            Connection => 'close',
          ),
        );
      }

      if ($request_uri =~ /=cats$/) {
        $test_results[6] = 'ok 7';
        $kernel->post( chunk => request => got_response =>
          # GET 'http://poe.perl.org/misc/test.html'
          # GET 'http://www.searchrequest.net/'
          # GET 'http://www.dack.com/'
          GET(
            'http://www.overture.com/images-affiliates/befree/ologo.gif',
            Connection => 'close',
          ),
        );
      }
    }
    elsif ($http_response->code == 404) {
      $request_path;
      $test_results[7] = 'ok 8' if $request_path =~ /ologo\.gif$/;
    }
  }
  # DEBUG and "client SECOND_RESPONSE: DONE";
}

#------------------------------------------------------------------------------

# Create a Client::Keepalive component
$cm = POE::Component::Client::Keepalive->new;

# Create a weeble component.
POE::Component::Client::HTTP->spawn(
  #MaxSize           => MAX_BIG_REQUEST_SIZE,
  Timeout           => 2,
  ConnectionManager => $cm,
);

# Create a weeble component.
POE::Component::Client::HTTP->spawn(
  Alias             => 'chunk',
  MaxSize           => MAX_BIG_REQUEST_SIZE,
  Timeout           => 5,
  FollowRedirects   => 1,
  Protocol          => 'HTTP/1.1',
  ConnectionManager => $cm,
);

# Create a session that will make some requests.
POE::Session->create(
  inline_states => {
    _start              => \&client_start,
    _stop               => \&client_stop,
    got_first_response  => \&client_got_first_response,
    got_response        => \&client_got_response,
    got_big_response    => \&client_got_big_response,
    got_stream_response => \&client_got_stream_response,
    got_redir_response  => \&client_got_redir_response,
    check_counts        => \&client_check_counts,
  },
);

# Run it all until done.
$poe_kernel->run();

exit;
