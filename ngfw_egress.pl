#!/usr/bin/perl -w
#TODO: 
#encoding options for xfer to obfuscate what's sent
#process stdin and stdout like netcat, interactive mode
#detect mss and adjust accordingly

use strict;
use warnings;
use IO::Select;
use IO::Socket::INET;
use Getopt::Std;
use POSIX qw( WNOHANG );

$| = 1;

my $parentpid = $$;
		my ($socket,$client_socket);
my $socket_open = 1;
my $no_packets = 1;
#use sigtrap 'handler' => \&myhanda, 'ABRT';
$SIG{ABRT} = \&myhanda;
sub myhanda
{
	print "caught SIGABRT, dying\n";
    $no_packets = 0;
}
#use sigtrap 'handler' => \&myhandi, 'ILL';
$SIG{ILL} = \&myhandi;
sub myhandi
{
	print "caught SIGILL, dying\n";
    $no_packets = 0;
}

my $scriptname = "ngfw_egress.pl";

my %opts = ();
getopts('lp:s:r:w:d:n:m:c:h', \%opts) || die usage();
my ($server,$client,$inter,$sport,$saddr,$infile,$outfile,$delay,$ppc,$mss,$code) = 0;
parse_opts(\%opts,\$server,\$client,\$inter,\$sport,\$saddr,\$infile,\$outfile,\$delay,\$ppc,\$mss,\$code,\@ARGV);

if ($inter) {
	my $kidpid;
	my $line = "";
	if ($server) {
		$socket = new IO::Socket::INET (
			LocalHost => $saddr, LocalPort => $sport, Proto => 'tcp', Listen => 5, Reuse => 1
		) or die "ERROR in Socket Creation : $!\n";
		$socket->autoflush(1);
		while ($socket_open) {
			$no_packets = 1;
			$client_socket = $socket->accept();
			$client_socket->autoflush(1);
			$client_socket->blocking(0);
			STDIN->autoflush(1);
			STDIN->blocking(0);
			select((select($socket), $|=1)[0]);
			select((select($client_socket), $|=1)[0]);
			select((select(STDIN), $|=1)[0]);
			select((select(STDOUT), $|=1)[0]);
		
			# split the program into two processes, identical twins
			die "can't fork: $!" unless defined($kidpid = fork());

			if ($kidpid) {      
				do {
					$client_socket->recv($line,1500);		
					if ($line) {
						print STDOUT $line;
						kill("TERM" => $kidpid) if ($kidpid);        # send SIGTERM to child
						$no_packets = 0;
					}
				} while ($no_packets);
			}
			else {                              
				# child copies standard input to the socket
				do {
					$line = <STDIN>;
					if ($line) {
						print $client_socket $line;
						$no_packets = 0;
						kill("ABRT" => getppid());        # send SIGABRT to child
					}
				} while ($no_packets);
				exit(0);
			}
			$client_socket->close();
		}
		$socket->close();
	} else {
		while ($socket_open) {
			$no_packets = 1;
			my $socket;
			my ($daddr,$dport) = @ARGV;
			# create a tcp connection to the specified host and port
			$socket = IO::Socket::INET->new(Proto     => "tcp",
							PeerAddr  => $daddr,
							PeerPort  => $dport)
			   	or die "can't connect to port $daddr on $dport: $!";
			$socket->autoflush(1);              # so output gets there right away
			print STDERR "[Connected to $daddr:$dport]\n";
			STDIN->autoflush(1);
			STDOUT->autoflush(1);
			$socket->blocking(0);
			#STDIN->blocking(0);
			select((select($socket), $|=1)[0]);
			select((select(STDIN), $|=1)[0]);
			select((select(STDOUT), $|=1)[0]);
		
			open PFH,">ngfw_egress.pid";
			print PFH $$;
			close PFH;

			# split the program into two processes, identical twins
			die "can't fork: $!" unless defined($kidpid = fork());
print "new fork\n";	
			if ($kidpid) {        
				# parent copies the socket to standard output
				do {
					$socket->recv($line,1500);		
					if ($line) {
						print STDOUT $line;
print "kill child\n";
						kill("TERM" => $kidpid) if ($kidpid);        # send SIGTERM to child
						$no_packets = 0;
						unlink "ngfw_egress.pid";
					}
				} while ($no_packets && -f "ngfw_egress.pid");
			}
			else {                
				do {
					$line = <STDIN>;
					if ($line) {
						print $socket $line;
						$no_packets = 0;
						unlink "ngfw_egress.pid";
						#kill("INT" => $ppid);        # send SIGABRT to child
					}
				} while ($no_packets);
				exit(0);		
			}
		}
		$socket->close();
	}
	
	
} else {
	if ($server && $outfile) {  # server will listen for connection and write out file
		my ($socket,$client_socket);
		$socket = new IO::Socket::INET (
			LocalHost => $saddr, LocalPort => $sport, Proto => 'tcp', Listen => 5, Reuse => 1
		) or die "ERROR in Socket Creation : $!\n";
		$socket->autoflush(1);

		my %output_hash = ();
		my $more = 1;
		do {
			$client_socket = $socket->accept();
			$client_socket->autoflush(1);
			
			my $pts = 1;
			my $buffer = "";
			do {
				$client_socket->recv($buffer,1500);
				if ($buffer =~ /^${code}_(\d+)_(\d+)_(.*)_SHUTITDOWN$/ms) {
					$output_hash{$1} = $3;
					$pts = $2;
					$more = 0;
				} elsif ($buffer =~ /^${code}_(\d+)_(\d+)_(.*)/ms) {
					$output_hash{$1} = $3;
					$pts = $2;
				} else {
					print STDERR "BAD CODE\n";
				}
			} while ($pts > 1 && $more);
			$client_socket->close();
		} while ($more);
		$socket->close();

		open FH, ">$outfile" or die "couldn't open: $!";
		binmode FH;
		my $i;
		for($i=0;$i<keys(%output_hash);$i++){
			print FH $output_hash{$i};
		}
		close FH;
		exit(0);
	} elsif ($server && $infile) {   # server will listen for connection and send file to client
		my ($socket,$client_socket);
		my ($buffer,$max_read);
		$socket = new IO::Socket::INET (
			LocalHost => $saddr, LocalPort => $sport, Proto => 'tcp', Listen => 5, Reuse => 1
		) or die "ERROR in Socket Creation : $!\n";
		$socket->autoflush(1);

		if ($infile ne "stdin") {
			open FH, "<$infile" or die "couldn't open: $!";
			binmode FH;
			my $filesize = -s $infile;
			
			my $pos = 0;
			my $read_size;
			my $index = 0;
			my $closing = "";
			while ($pos < $filesize) {	
				$client_socket = $socket->accept();
				$client_socket->autoflush(1);
			
				for(my $pts = $ppc; $pts > 0 && $pos < $filesize; $pts--) {
					my $prefix = $code . "_" . $index . "_" . $pts . "_";
					$max_read = $mss - length($prefix."_SHUTITDOWN");
					$max_read = 1 if ($max_read < 1);
					if ($filesize-$pos > $max_read) {
						$read_size = $max_read;
						$closing = "";
					} else {
						$read_size = $filesize-$pos;
						$closing = "_SHUTITDOWN";
					}
				
					seek (FH, $pos, 0);			
					read (FH, $buffer, $read_size);	
					$client_socket->send("$prefix" . "$buffer" . $closing);
				
					$pos += $read_size;
					select(undef, undef, undef, $delay) if ($pos < $filesize);
					$index++;
				}
			}
			$socket->close();
			close FH;
		} else {
                        my $pos = 0;
                        my $read_size;
                        my $index = 0;
                        my $closing = "";
			my $client_socket;
                        $ppc = 1;
                        select((select(STDIN), $|=1)[0]);
                        STDIN->autoflush(1);
			binmode STDIN;
                        my $line = "";
                        while ($socket_open && defined($line)) {
				$client_socket = $socket->accept();
				$client_socket->autoflush(1);
                        	while ($socket_open && defined($line) && $ppc == 1) {
                                	$line = <STDIN>;
					last if (!defined($line));

					my $last = 0;
					my $prefix = $code . "_" . $index . "_" . $ppc . "_";
					$max_read = $mss - length($prefix . "_SHUTITDOWN");
					$max_read = 1 if ($max_read < 1);
					if (length($line) > $max_read) {
						$pos = 0;
						while ($pos < length($line)) {
							my $prefix = $code . "_" . $index . "_" . $ppc . "_";
							if ($max_read > length($line) - $pos) {
								$max_read = length($line) - $pos; 
								$last = 1;
							}
							$client_socket->send("$prefix" . substr($line,$pos,$max_read) . $closing);
							$client_socket->close();
							$client_socket = $socket->accept();
							$client_socket->autoflush(1);
							$pos += $max_read;
							select(undef, undef, undef, $delay);
							$index++;
						}
					} else {
						my $prefix = $code . "_" . $index . "_" . $ppc . "_";
                                		$client_socket->send("$prefix" . "$line" . $closing);
                                		$pos += length($line);
                                		select(undef, undef, undef, $delay);
                                		$index++;
						$ppc--;
					}
				}
                                $client_socket->close() if ($socket_open && defined($line));
				$ppc = 1;
                        }
                        $client_socket->send($code . "_" . $index . "_1__SHUTITDOWN");
                        $client_socket->close();
                }
	} elsif ($client && $infile) {   # client will connect to server and send file
		if (@ARGV != 2) {
			print "host and port must be given after options\n\n";
			usage();
			exit(1);
		}
		my ($daddr,$dport) = @ARGV;
		my ($socket,$buffer,$max_read);

		if ($infile ne "stdin") {
			open FH, "<$infile" or die "couldn't open: $!";
			binmode FH;
			my $filesize = -s $infile;
		
			my $pos = 0;
			my $read_size;
			my $index = 0;
			my $closing = "";
			while ($pos < $filesize) {	
				$socket = new IO::Socket::INET (
					PeerHost => $daddr, PeerPort => $dport, Proto => 'tcp',
				) or die "ERROR in Socket Creation : $!\n";
				$socket->autoflush(1);
				
				for(my $pts = $ppc; $pts > 0 && $pos < $filesize; $pts--) {
					my $prefix = $code . "_" . $index . "_" . $pts . "_";
					$max_read = $mss - length($prefix."_SHUTITDOWN");
					$max_read = 1 if ($max_read < 1);
					if ($filesize-$pos > $max_read) {
						$read_size = $max_read;
						$closing = "";
					} else {
						$read_size = $filesize-$pos;
						$closing = "_SHUTITDOWN";
					}
					
					seek (FH, $pos, 0);			
					read (FH, $buffer, $read_size);	
					$socket->send("$prefix" . "$buffer" . $closing);
					
					$pos += $read_size;
					select(undef, undef, undef, $delay) if ($pos < $filesize);
					$index++;
				}
				$socket->close();
			}
			close FH;
		} else {
			my $pos = 0;
			my $read_size;
			my $index = 0;
			my $closing = "";
			$ppc = 1;
			select((select(STDIN), $|=1)[0]);
			STDIN->autoflush(1);
			binmode STDIN;
			my $line = "";
			while ($socket_open && defined($line) && $ppc == 1) {
                               	$line = <STDIN>;
				last if (!defined($line));

				$socket = new IO::Socket::INET (
					PeerHost => $daddr, PeerPort => $dport, Proto => 'tcp',
				) or die "ERROR in Socket Creation : $!\n";
				$socket->autoflush(1);
				
				my $last = 0;
				my $prefix = $code . "_" . $index . "_" . $ppc . "_";
				$max_read = $mss - length($prefix . "_SHUTITDOWN");
				$max_read = 1 if ($max_read < 1);

				if (length($line) > $max_read) {
					$pos = 0;
					while ($pos < length($line)) {
						my $prefix = $code . "_" . $index . "_" . $ppc . "_";
						if ($max_read > length($line) - $pos) {
							$max_read = length($line) - $pos;
							$last = 1;
						}
						$socket->send("$prefix" . substr($line,$pos,$max_read) . $closing);
						$socket->close() if !$last;
						$socket = new IO::Socket::INET (
							PeerHost => $daddr, PeerPort => $dport, Proto => 'tcp',
						) or die "ERROR in Socket Creation : $!\n" if !$last;
						$socket->autoflush(1) if !$last;
						$pos += $max_read;
						select(undef, undef, undef, $delay);
						$index++;
					}
				} else {
					my $prefix = $code . "_" . $index . "_" . $ppc . "_";
					$socket->send("$prefix" . "$line" . $closing);
					$pos += length($line);
					select(undef, undef, undef, $delay);
					$index++;
				}
				$socket->close();
			}
			$socket = new IO::Socket::INET (
				PeerHost => $daddr, PeerPort => $dport, Proto => 'tcp',
			) or die "ERROR in Socket Creation : $!\n";
			$socket->autoflush(1);
			$socket->send($code . "_" . $index . "_" . $ppc . "__SHUTITDOWN");
			$socket->close();
		}
		
	} elsif ($client && $outfile) {   # client will connect to server and receive file
		if (@ARGV != 2) {
			print "host and port must be given after options\n\n";
			usage();
			exit(1);
		}
		my ($daddr,$dport) = @ARGV;
		my ($socket,$buffer,$max_read);

		my %output_hash = ();
		my $more = 1;
		do {
			$socket = new IO::Socket::INET (
				PeerHost => $daddr, PeerPort => $dport, Proto => 'tcp',
			) or die "ERROR in Socket Creation : $!\n";
			$socket->autoflush(1);
			
			my $pts = 0;
			my $buffer = "";
			do {
				$socket->recv($buffer,1500);
				if ($buffer =~ /^${code}_(\d+)_(\d+)_(.*)_SHUTITDOWN$/ms) {
					$output_hash{$1} = $3;
					$pts = $2;
					$more = 0;
				} elsif ($buffer =~ /^${code}_(\d+)_(\d+)_(.*)/ms) {
					$output_hash{$1} = $3;
					$pts = $2;
				} else {
					print STDERR "BAD CODE\n";
				}
			} while ($pts > 1 && $more);
			$socket->close();
		} while ($more);
		
		open FH, ">$outfile" or die "couldn't open: $!";
		binmode FH;
		my $i;
		for($i=0;$i<keys(%output_hash);$i++){
			print FH $output_hash{$i};
		}
		close FH;
		exit(0);	
	}
}
exit(0);

sub usage {
	print <<EOF;
\nusage: (client) $scriptname [options] dsthost dstport  	
       (server) $scriptname -l -p port [options]

OPTIONS:
        -h               Print this help message
        -l               run in server mode
        -p port          Local port for server to listen on
        -s ipaddr        Local IP address to bind to
                         default: 0.0.0.0
        -r file          file to read from on client side
        -w file          file to write to on server side
        -d delay         time between each packet sent
                         default: 0 (server receives) or 0.5 (server sends)
        -n packets       number of packets to send per TCP connection
                         default: 1
        -m size          maximum segment size, bytes of the file that will be
                         sent per packet
                         default: 1460
        -c code          code sent at beginning of each packet to link 
                         default: 12345
EOF
}

sub parse_opts {
	my ($opts_ref,$server,$client,$inter,$sport,$saddr,$infile,$outfile,$delay,$ppc,$mss,$code,$argv) = @_;
	my ($daddr,$dport) = @$argv;
	my $opts = %$opts_ref;
	
	if (defined($opts{'h'})) {
		usage();
		exit(0);
	}
	
	if (defined($opts{'l'})) {
		$$server = 1;
		$$client = 0;
		if (@ARGV != 0 || !defined($opts{'p'})) {
			usage();
			exit(1);
		}		
	} else {
		$$server = 0;
		$$client = 1;
		if (@$argv != 2 || !(defined($daddr) && defined($dport))) {
			usage();
			exit(1);
		}
	}
	
	if (!(defined($opts{'r'}) || defined($opts{'w'}))) {
		$$inter = 1;
	}
	
	if (defined($opts{'s'})) {
		$$saddr = $opts{'s'};
	} else {
		$$saddr = "0.0.0.0";
	}
	
	if (defined($opts{'p'})) {
		$$sport = $opts{'p'};
	}
	
	if (defined($opts{'w'})) {
		$$outfile = $opts{'w'};
	}
	
	if (defined($opts{'r'})) {
		$$infile = $opts{'r'};
	}
	
	if (defined($opts{'d'})) {
		$$delay = $opts{'d'};
	} else {
		$$delay = 0;
		#if (defined($opts{'l'}) && defined($opts{'r'})) {
		    #$$delay = .5;
		#}
	}
	
	if (defined($opts{'n'})) {
		$$ppc = $opts{'n'};
	} else {
		$$ppc = 1;
	}
	
	if (defined($opts{'m'})) {
		$$mss = $opts{'m'};
	} else {
		$$mss = 1460;
	}
	
	if (defined($opts{'c'})) {
		$$code = $opts{'c'};
	} else {
		$$code = 12345;
	}
}




#http://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=1&ved=0CG0QFjAA&url=http%3A%2F%2Fcaspian.dotconf.net%2Fmenu%2FSoftware%2FMisc%2Fnetcat.pl&ei=NYMeUKyjC6GO2AWpz4G4CA&usg=AFQjCNETbnOBHncu-YdX1QBWDfKLfxJ4eA
######################################################################
##  Function: RC4 ($passphrase, $plaintext) or
##                ($passphrase, $encrypted)
##  
##  The following code was pulled from the perl package:
##  Crypt::RC4 - Perl implementation of the RC4 encryption algorithm
##  
##  Synopsis:
##            $encrypted = RC4( $passphrase, $plaintext );
##            $decrypt = RC4( $passphrase, $encrypted );
######################################################################
sub RC4 {
        my $x = 0;
        my $y = 0;
        
        my $key = shift;
        my @k = unpack( 'C*', $key );
        my @s = 0..255;
        
        for ($x = 0; $x != 256; $x++) {
                $y = ( $k[$x % @k] + $s[$x] + $y ) % 256;
                @s[$x, $y] = @s[$y, $x];
        }
 
        $x = $y = 0;
 
        my $z = undef;
        
        for ( unpack( 'C*', shift ) ) {
                $x = ($x + 1) % 256;
                $y = ( $s[$x] + $y ) % 256;
                @s[$x, $y] = @s[$y, $x];
                $z .= pack ( 'C', $_ ^= $s[( $s[$x] + $s[$y] ) % 256] );
        }
 
        return $z;
}

use sigtrap 'handler' => \&myhand, 'INT';
sub myhand
{
	print "caught SIGINT, closing socket\n";
	if ($inter) {
		$no_packets = 0;
	} else {
		$socket_open = 0;
	}
}








#parent crypt
		# my $data = "";
		# while (<$data_socket>) {
		#	if ($conf{'crypt'}) {
				## We want to break data into 16384 byte chuncks
		#		$data .= $_;
		#		if (length($data) >= 16384) {
		#			$data =~ s/(.{16384})//s;
		#			print RC4($conf{'passphrase'}, $&);
		#		}
		#	} else {
				# print $_;
		#	}
		# }
		## If crypt'ing check for leftovers
		#if ($conf{'crypt'}) {
		#	print RC4($conf{'passphrase'}, $data) if ($data);
		#}






#client crypt
    # if ($conf{'crypt'}) {
      # We want to break data into 16384 byte chuncks (this is so the encrypted data doesn't get out of allignment)
      # $data .= $_;
      # if (length($data) >= 16384) {
        # $data =~ s/(.{16384})//s;
        # $_ = RC4($conf{'passphrase'}, $&);
        # print SERVER $_;
      # }
    # }
    # else {
      # print SERVER $_;
    # }
  # }
  # If crypt'ing check for leftovers
  # if ($conf{'crypt'}) {
    # $_ = RC4($conf{'passphrase'}, $data) if ($data);
    # print SERVER $_;
  # }
