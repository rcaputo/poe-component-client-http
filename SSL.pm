# $Id$
# License and documentation are after __END__.

package POE::Component::Client::HTTP::SSL;

use strict;

use vars qw($VERSION);
$VERSION = (qw($Revision$ ))[1];

use Net::SSLeay::Handle;
use vars qw(@ISA);
@ISA = qw(Net::SSLeay::Handle);

sub READ {
  my ($socket, $buf, $len, $offset) = \ (@_);
  my $ssl = $$socket->_get_ssl();
  defined($$offset) or
    return length($$buf = Net::SSLeay::read($ssl, $$len));

  defined(my $read = Net::SSLeay::read($ssl, $$len))
    or return undef;

  my $buf_len = length($$buf);
  $$offset > $buf_len and $$buf .= chr(0) x ($$offset - $buf_len);
  substr($$buf, $$offset) = $read;
  return length($read);
}

1;

__END__

=head1 NAME

POE::Component::Client::HTTP::SSL - non-blocking SSL file handles

=head1 SYNOPSIS

  See Net::SSLeay::Handle

=head1 DESCRIPTION

This is a temporary subclass of Net::SSLeay::Handle with what I
consider proper read() and sysread() semantics.  This module will go
away if or when Net::SSLeay::Handle adopts these semantics.

POE::Component::Client::HTTP::SSL functions identically to
Net::SSLeay::Handle, but the READ function does not block until LENGTH
bytes are read.

=head1 SEE ALSO

Net::SSLeay::Handle

=head1 BUGS

None known.

=head1 AUTHOR & COPYRIGHTS

POE::Component::Client::HTTP::SSL is Copyright 1999-2002 by Rocco
Caputo.  All rights are reserved.  This module is free software; you
may redistribute it and/or modify it under the same terms as Perl
itself.

Rocco may be contacted by e-mail via rcaputo@cpan.org.

=cut
