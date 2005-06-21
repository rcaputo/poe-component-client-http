#!/usr/bin/perl
# $Id$

use strict;
use lib qw(./mylib);
use ExtUtils::MakeMaker;

# Touch CHANGES so it exists.
open(CHANGES, ">>CHANGES") and close CHANGES;

my %prereq = (
  'POE'             => 0.31,
  'HTTP::Request'   => 1.30,
  'HTTP::Response'  => 1.37,
  'URI'             => 1.24,
  'POE::Component::Client::Keepalive' => 0.02,
);

# Write that makefile.
WriteMakefile(
  NAME         => 'POE::Component::Client::HTTP',
  AUTHOR       => 'Rocco Caputo <rcaputo@cpan.org>',
  ABSTRACT     => 'Non-blocking/concurrent HTTP queries with POE',
  VERSION_FROM => 'HTTP.pm',
  PM           => {
    'HTTP.pm'           => '$(INST_LIBDIR)/HTTP.pm',
    'Request.pm'        => '$(INST_LIBDIR)/HTTP/Request.pm',
    'RequestFactory.pm' => '$(INST_LIBDIR)/HTTP/RequestFactory.pm',
    'HTTPHead.pm'       => '$(INST_LIBDIR)/../../Filter/HTTPHead.pm',
    'HTTPChunk.pm'      => '$(INST_LIBDIR)/../../Filter/HTTPChunk.pm',
  },
  PREREQ_PM    => \%prereq,
  dist         => {
    COMPRESS   => 'gzip -9f',
    SUFFIX     => 'gz',
    PREOP      => (
      'svn-log.perl --repo https://thirdlobe.com/svn/poco-client-http | ' .
      'tee ./$(DISTNAME)-$(VERSION)/CHANGES > ./CHANGES'
    ),
  },
);
