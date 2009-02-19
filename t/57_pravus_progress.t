# See rt.cpan.org ticket 36627.

use warnings;
use strict;

use Test::More tests => 2;
use HTTP::Request::Common qw(GET);
use POE;
use POE::Component::Client::HTTP;

POE::Component::Client::HTTP->spawn(
  Alias           => 'ua',
  Streaming       => 4096,
  FollowRedirects => 32,
);

POE::Session->create(
  package_states => [
    main => [qw( _start http_response http_progress _stop )],
  ],
);

POE::Kernel->run();
exit 0;

sub _start {
  $_[HEAP]{got_response} = 0;
  $_[HEAP]{got_progress} = 0;
  $_[KERNEL]->post(
    ua => request => 'http_response',
    GET("http://yahoo.com"), 'id', 'http_progress'
  );
}

sub http_response {
  $_[HEAP]{got_response}++;
}

sub http_progress {
  $_[HEAP]{got_progress}++;
}

sub _stop {
  ok($_[HEAP]{got_response}, "got response: $_[HEAP]{got_response}");
  ok($_[HEAP]{got_progress}, "got progress: $_[HEAP]{got_progress}");
}
