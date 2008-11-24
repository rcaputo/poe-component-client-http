#!/usr/bin/perl
# $Id$

use strict;
use lib qw(./mylib);
use ExtUtils::MakeMaker;

# Touch CHANGES so it exists.
open(CHANGES, ">>CHANGES") and close CHANGES;

my %prereq = (
  'POE'                => 0.3202,
  'HTTP::Request'      => 1.30,
  'HTTP::Response'     => 1.37,
  'URI'                => 1.24,
  'Net::HTTP::Methods' => 0.02,
  'POE::Component::Client::Keepalive' => 0.22,
  'Test::POE::Server::TCP' => 0,
);

# Write that makefile.
WriteMakefile(
  NAME         => 'POE::Component::Client::HTTP',
  AUTHOR       => 'Rocco Caputo <rcaputo@cpan.org>',
  ABSTRACT     => 'Non-blocking/concurrent HTTP queries with POE',
  LICENSE      => 'perl',
  VERSION_FROM => 'lib/POE/Component/Client/HTTP.pm',
  PREREQ_PM    => \%prereq,
  dist         => {
    COMPRESS   => 'gzip -9f',
    SUFFIX     => 'gz',
    PREOP      => (
      'svn-log.perl | tee ./$(DISTNAME)-$(VERSION)/CHANGES > ./CHANGES'
    ),
  },
);
