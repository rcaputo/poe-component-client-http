#!/usr/bin/perl
# $Id$

use strict;
use lib qw(./mylib);
use ExtUtils::MakeMaker;
use ExtUtils::AutoInstall;

# Touch CHANGES so it exists.
open(CHANGES, ">>CHANGES") and close CHANGES;

my %prereq = (
  'POE'					=> 0.31,
  'HTTP::Request'			=> 1.30,
  'HTTP::Response'			=> 1.37,
  'URI'					=> 1.24,
  'POE::Component::Client::Keepalive'	=> 0.02,
);

# Prompt for optional things.
# TODO - Move to PoCo::Client::Keepalive.
ExtUtils::AutoInstall->import(
  -version => '0.54',
  -core    => [ %prereq ],
  "Optional modules for SSL support." => [
    -default              => 0,
    'Net::SSLeay'         => 1.17,
    'Net::SSLeay::Handle' => 0.61,
  ],
);

# Write that makefile.
WriteMakefile(
  NAME         => 'POE::Component::Client::HTTP',
  AUTHOR       => 'Rocco Caputo <rcaputo@cpan.org>',
  ABSTRACT     => 'POE component for non-blocking/concurrent HTTP queries.',
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
      'cvs-log.perl | ' .
      'tee ./$(DISTNAME)-$(VERSION)/CHANGES > ./CHANGES'
    ),
  },
);
