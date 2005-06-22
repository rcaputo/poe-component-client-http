# $Id$

package POE::Filter::HTTPChunk;
use strict;

use Carp;
use bytes;

use HTTP::Response;

sub FRAMING_BUFFER   () { 0 }
sub CURRENT_STATE    () { 1 }
sub CHUNK_SIZE       () { 2 }
sub CHUNK_BUFFER     () { 3 }
sub TRAILER_HEADERS  () { 4 }

sub STATE_SIZE    () { 0x01 }  # waiting for a status line
sub STATE_DATA    () { 0x02 }  # received status, looking for header or end
sub STATE_TRAILER () { 0x04 }  # received status, looking for header or end

sub DEBUG () { 0 }

sub new {
  my $type = shift;

  my $self = bless [
    [],          # FRAMING_BUFFER
    STATE_SIZE, # CURRENT_STATE
    0,          # CHUNK_SIZE
    '',          # CHUNK_BUFFER
    undef,      # TRAILER_HEADERS
  ], $type;

  $self;
}

my $HEX = qr/[\dA-Fa-f]/o;

=for later

my $TEXT = qr/[^[:cntrl:]]/o;
my $qdtext = qr/[^[:cntrl:]\"]/o; #<any TEXT except <">>
my $quoted_pair = qr/\\[[:ascii:]]/o;
my $quoted_string = qr/\"(?:$qdtext|$quoted_pair)\"/o;
my $separators = "[^()<>@,;:\\"\/\[\]\?={} \t";
my $notoken = qr/(?:[[:cntrl:]$separators]/o;

my $chunk_ext_name = $token;
my $chunk_ext_val = qr/(?:$token|$quoted_string)/o;

my $chunk_extension = qr/(?:;$chunk_ext_name(?:$chunk_ext_val)?)/o;

=cut

sub get_one_start {
  my ($self, $chunks) = @_;

  #warn "GOT MORE DATA";
  push (@{$self->[FRAMING_BUFFER]}, @$chunks);
  #warn "NUMBER OF CHUNKS is now ", scalar @{$self->[FRAMING_BUFFER]};
}

sub get_one {
  my $self = shift;

  my $retval = [];
  while (defined (my $chunk = shift (@{$self->[FRAMING_BUFFER]}))) {
    #warn "CHUNK IS SIZE ", length($chunk);
    #warn join(
    #  ",", map {sprintf("%02X", ord($_))} split (//, substr ($chunk, 0, 10))
    #);
    #warn "NUMBER OF CHUNKS is ", scalar @{$self->[FRAMING_BUFFER]};
    DEBUG and warn "STATE is ", $self->[CURRENT_STATE];

    # if we're not in STATE_DATA, we need to have a newline sequence
    # in our hunk of content to find out how far we are.
    unless ($self->[CURRENT_STATE] & STATE_DATA) {
      if ($chunk !~ /.\015?\012/s) {
        #warn "SPECIAL CASE";
        if (@{$self->[FRAMING_BUFFER]} == 0) {
          #warn "pushing $chunk back";
          unshift (@{$self->[FRAMING_BUFFER]}, $chunk);
          return $retval;
        }
        else {
          $chunk .= shift (@{$self->[FRAMING_BUFFER]});
          #warn "added to $chunk";
        }
      }
    }

    if ($self->[CURRENT_STATE] & STATE_SIZE) {
      DEBUG and warn "Finding chunk length marker";
      if ($chunk =~ s/^($HEX+)(?:;.*)?\015?\012//s) {
        my $length = hex($1);
        DEBUG and warn "Chunk should be $length bytes";
        $self->[CHUNK_SIZE] = $length;
        if ($length == 0) {
          $self->[TRAILER_HEADERS] = HTTP::Headers->new;
          $self->[CURRENT_STATE] = STATE_TRAILER;
        }
        else {
          $self->[CURRENT_STATE] = STATE_DATA;
        }
      }
      else {
        # ok, this is a hack. skip to the next line if we
        # don't find the chunk length, it might just be an extra
        # line or something, and the chunk length always is on
        # a line of it's own, so this seems the only way to recover
        # somewhat.
        #TODO: after discussing on IRC, the concensus was to return
        #an error Response here, and have the client shut down the
        #connection.
        DEBUG and warn "DIDN'T FIND CHUNK LENGTH $chunk";
        my $replaceN = $chunk =~ s/.*?\015?\012//s;
        unshift (@{$self->[FRAMING_BUFFER]}, $chunk) if ($replaceN == 1);
        return $retval;
      }
    }

    if ($self->[CURRENT_STATE] & STATE_DATA) {
      my $len = $self->[CHUNK_SIZE] - length ($self->[CHUNK_BUFFER]);
      DEBUG and
        warn "going for length ", $self->[CHUNK_SIZE], " (need $len more)";
      my $newchunk = delete $self->[CHUNK_BUFFER];
      $newchunk .= substr ($chunk, 0, $len, '');
      #warn "got " . length($newchunk) . " bytes of data";
      if (length $newchunk != $self->[CHUNK_SIZE]) {
        #smaller, so wait
        $self->[CHUNK_BUFFER] = $newchunk;
        next;
      }
      $self->[CURRENT_STATE] = STATE_SIZE;
      #warn "BACK TO FINDING CHUNK SIZE $chunk";
      if (length ($chunk) > 0) {
        DEBUG and warn "we still have a bit $chunk ", length($chunk);
        #warn "'", substr ($chunk, 0, 10), "'";
        $chunk =~ s/^\015?\012//s;
        #warn "'", substr ($chunk, 0, 10), "'";
        unshift (@{$self->[FRAMING_BUFFER]}, $chunk);
      }
      push @$retval, $newchunk;
      #return [$newchunk];
    }

    if ($self->[CURRENT_STATE] & STATE_TRAILER) {
      while ($chunk =~ s/^([-\w]+):\s*(.*?)\015?\012//s) {
        DEBUG and warn "add trailer header $1";
        $self->[TRAILER_HEADERS]->push_header ($1, $2);
      }
      #warn "leftover: ", $chunk;
      #warn join (
      #  ",",
      #  map {sprintf("%02X", ord($_))} split (//, substr ($chunk, 0, 10))
      #), "\n";
      if ($chunk =~ s/^\015?\012//s) {
        my $headers = delete $self->[TRAILER_HEADERS];

        push (@$retval, $headers);
        DEBUG and warn "returning ", scalar @$retval, "responses";
        unshift (@{$self->[FRAMING_BUFFER]}, $chunk) if (length $chunk);
        return $retval;
      }
      unshift (@{$self->[FRAMING_BUFFER]}, $chunk);
    }
  }
  return $retval;
}

=for future

sub put {
  die "not implemented yet";
}

=cut

sub get_pending {
  my $self = shift;
  return $self->[FRAMING_BUFFER] if @{$self->[FRAMING_BUFFER]};
  return undef;
}
