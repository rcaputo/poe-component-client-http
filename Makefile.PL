#!/usr/bin/perl
# $Id: Makefile.PL,v 1.20 2004/02/23 23:24:31 rcaputo Exp $

use strict;
use lib qw(./mylib);
use ExtUtils::MakeMaker;
use ExtUtils::AutoInstall;

# Touch CHANGES so it exists.
open(CHANGES, ">>CHANGES") and close CHANGES;

my %prereq = (
  'POE'            => 0.27,
  'HTTP::Request'  => 1.30,
  'HTTP::Response' => 1.37,
  'URI'            => 1.24,
  'HTML::Parser'   => 3.33,  # For HTML::HeadParser
);

# Prompt for optional things.
ExtUtils::AutoInstall->import
  ( -version => '0.54',
    -core    => [ %prereq ],
    "Optional modules for SSL support." =>
    [ -default              => 0,
      'Net::SSLeay'         => 1.17,
      'Net::SSLeay::Handle' => 0.61,
    ],
  );

# Write that makefile.
WriteMakefile
  ( NAME         => 'POE::Component::Client::HTTP',
    AUTHOR       => 'Rocco Caputo <rcaputo@cpan.org>',
    ABSTRACT     => 'POE component for non-blocking/concurrent HTTP queries.',
    VERSION_FROM => 'HTTP.pm',
    PM           => { 'HTTP.pm'        => '$(INST_LIBDIR)/HTTP.pm',
                      'SSL.pm'         => '$(INST_LIBDIR)/HTTP/SSL.pm',
                    },
    PREREQ_PM    => \%prereq,
    dist         =>
    { COMPRESS   => 'gzip -9f',
      SUFFIX     => 'gz',
      PREOP      => ( 'cvs-log.perl | ' .
                      'tee ./$(DISTNAME)-$(VERSION)/CHANGES > ./CHANGES'
                    ),
    },
  );
