#!/usr/bin/perl
# $Id$

use strict;
use lib qw(./mylib);
use ExtUtils::MakeMaker;
use ExtUtils::AutoInstall;

# Ensure that ./CHANGES exists.
open(CHANGES, ">>CHANGES");
close CHANGES;

# Prompt for optional things.
ExtUtils::AutoInstall->import
  ( -version => '0.32',
    -core    =>
    [ 'POE'            => 0.22,
      'HTTP::Request'  => 1.27,
      'HTTP::Response' => 1.33,
      'URI'            => 1.11,
    ],
    "Optional modules for SSL support." =>
    [ -default              => 0,
      'Net::SSLeay'         => 1.17,
      'Net::SSLeay::Handle' => 0.61,
    ],
  );

# To mollify a recent warning in POE::Kernel.
$POE::Kernel::poe_kernel->run();

# Write that makefile.
WriteMakefile
  ( NAME         => 'POE::Component::Client::HTTP',
    AUTHOR       => 'Rocco Caputo <troc+poe@pobox.com>',
    ABSTRACT     => 'POE component for non-blocking/concurrent HTTP queries.',
    VERSION_FROM => 'HTTP.pm',
    PM           => { 'HTTP.pm'        => '$(INST_LIBDIR)/HTTP.pm',
                      'SSL.pm'         => '$(INST_LIBDIR)/HTTP/SSL.pm',
                    },
    PREREQ_PM    => { 'POE'                 => 0.1106,
                      'HTTP::Request'       => 1.27,
                      'HTTP::Response'      => 1.33,
                      'URI'                 => 1.11,
                    },
    dist         =>
    { COMPRESS   => 'gzip -9f',
      SUFFIX     => 'gz',
      PREOP      => ( 'cvs-log.perl | ' .
                      'tee ./$(DISTNAME)-$(VERSION)/CHANGES > ./CHANGES'
                    ),
    },
  );
