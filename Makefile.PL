#!/usr/bin/perl
# $Id$

use ExtUtils::MakeMaker;

# Ensure that ./CHANGES exists.
open(CHANGES, ">>CHANGES");
close CHANGES;

WriteMakefile
  ( NAME         => 'POE::Component::Client::HTTP',
    AUTHOR       => 'Rocco Caputo <troc+poe@netrus.net>',
    ABSTRACT     => 'POE component for non-blocking/concurrent HTTP queries.',
    VERSION_FROM => 'HTTP.pm',

    PM           => { 'HTTP.pm'        => '$(INST_LIBDIR)/HTTP.pm',
                      'SSL.pm'         => '$(INST_LIBDIR)/HTTP/SSL.pm',
                    },
    PREREQ_PM    => { 'POE'                 => 0.1106,
                      'HTTP::Request'       => 1.27,
                      'HTTP::Response'      => 1.33,
                      'Net::SSLeay::Handle' => 0.61,
                      'URI'                 => 1.11,
                    },
    dist         =>
    { COMPRESS   => 'gzip -9f',
      SUFFIX     => 'gz',
      PREOP      => ( 'cvs2cl.pl -l "-d\'a year ago<\'" ' .
                    '--utc --stdout > $(DISTNAME)-$(VERSION)/CHANGES'
                    ),
    },
  );
