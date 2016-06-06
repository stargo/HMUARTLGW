##############################################
# $Id$

use Crypt::Rijndael;
use Digest::MD5;
use Time::HiRes qw(gettimeofday time);
use Time::Local;

use constant {
	HMUARTLGW_OS_GET_APP            => "00",
	HMUARTLGW_OS_GET_FIRMWARE       => "02",
	HMUARTLGW_OS_CHANGE_APP         => "03",
	HMUARTLGW_OS_ACK                => "04",
	HMUARTLGW_OS_UNSOL_CREDITS      => "05",
	HMUARTLGW_OS_NORMAL_MODE        => "06",
	HMUARTLGW_OS_UPDATE_MODE        => "07",
	HMUARTLGW_OS_GET_CREDITS        => "08",
	HMUARTLGW_OS_GET_SERIAL         => "0B",
	HMUARTLGW_OS_SET_TIME           => "0E",

	HMUARTLGW_APP_SET_HMID          => "00",
	HMUARTLGW_APP_GET_HMID          => "01",
	HMUARTLGW_APP_SEND              => "02",
	HMUARTLGW_APP_SET_CURRENT_KEY   => "03", #key index 
	HMUARTLGW_APP_ACK               => "04",
	HMUARTLGW_APP_RECV              => "05",
	HMUARTLGW_APP_ADD_PEER          => "06",
	HMUARTLGW_APP_REMOVE_PEER       => "07",
	HMUARTLGW_APP_GET_PEERS         => "08",
	HMUARTLGW_APP_PEER_ADD_AES      => "09",
	HMUARTLGW_APP_PEER_REMOVE_AES   => "0A",
	HMUARTLGW_APP_SET_OLD_KEY       => "0F", #key index
	HMUARTLGW_APP_DEFAULT_HMID      => "10",

	HMUARTLGW_ACK                   => "01",
	HMUARTLGW_ACK_WITH_DATA         => "07",
	HMUARTLGW_ACK_EINPROGRESS       => "08",

        HMUARTLGW_DST_OS                => 0,
        HMUARTLGW_DST_APP               => 1,

	HMUARTLGW_STATE_NONE            => 0,
	HMUARTLGW_STATE_QUERY_APP       => 1,
	HMUARTLGW_STATE_ENTER_APP       => 2,
	HMUARTLGW_STATE_GETSET_PARAMETERS  => 3,
	HMUARTLGW_STATE_SET_TIME        => 4,
	HMUARTLGW_STATE_SET_HMID        => 5,
	HMUARTLGW_STATE_GET_HMID        => 6,
	HMUARTLGW_STATE_GET_DEFAULT_HMID => 7,
	HMUARTLGW_STATE_GET_PEERS       => 8,
	HMUARTLGW_STATE_KEEPALIVE_INIT  => 96,
	HMUARTLGW_STATE_KEEPALIVE_SENT  => 97,
	HMUARTLGW_STATE_SEND            => 98,
	HMUARTLGW_STATE_RUNNING         => 99,
};

sub HMUARTLGW_Initialize($)
{
	my ($hash) = @_;

	require "$attr{global}{modpath}/FHEM/DevIo.pm";


	$hash->{ReadyFn}   = "HMUARTLGW_Ready";
	$hash->{ReadFn}    = "HMUARTLGW_Read";
	$hash->{WriteFn}   = "HMUARTLGW_Write";
	$hash->{DefFn}     = "HMUARTLGW_Define";
	$hash->{UndefFn}   = "HMUARTLGW_Undefine";
	$hash->{SetFn}     = "HMUARTLGW_Set";
	$hash->{GetFn}     = "HMUARTLGW_Get";
	$hash->{AttrFn}    = "HMUARTLGW_Attr";


	$hash->{Clients} = ":CUL_HM:";
	my %ml = ( "1:CUL_HM" => "^A......................" );
	$hash->{MatchList} = \%ml;

	$hash->{AttrList}= "hmId ".
	                   "lgwPw ";
}

sub HMUARTLGW_Read($);
sub HMUARTLGW_send($$$);
sub HMUARTLGW_send_frame($$);
sub HMUARTLGW_crc16($);
sub HMUARTLGW_encrypt($$);
sub HMUARTLGW_decrypt($$);

sub HMUARTLGW_DoInit($)
{
	my ($hash) = @_;
	my $name = $hash->{NAME};

	$hash->{CNT} = 0x00;
	delete($hash->{DEVCNT});
	delete($hash->{crypto});
	delete($hash->{keepAlive});
	$hash->{DevState} = HMUARTLGW_STATE_NONE;

	$hash->{LGW_Init} = 1 if ($hash->{DevType} =~ m/^LGW/);

	RemoveInternalTimer($hash);

	if ($hash->{DevType} eq "LGW") {
		my $keepAlive = {
			NR => $devcount++,
			NAME => "${name}:keepAlive",
			STATE => "uninitialized",
			TYPE => $hash->{TYPE},
			TEMPORARY => 1,
			directReadFn => \&HMUARTLGW_Read,
			DevType => "LGW-KeepAlive",
			lgwHash => $hash,
		};

		$attr{$keepAlive->{NAME}}{room} = "hidden";
		$defs{$keepAlive->{NAME}} = $keepAlive;

		DevIo_CloseDev($keepAlive);
		$keepAlive->{DeviceName} = $hash->{DEF}.":2001";
		DevIo_OpenDev($keepAlive, 0, "HMUARTLGW_DoInit");
		$hash->{keepAlive} = $keepAlive;
	}

	InternalTimer(gettimeofday()+1, "HMUARTLGW_StartInit", $hash, 0);

	return;
}

sub HMUARTLGW_Define($$)
{
	my ($hash, $def) = @_;
	my @a = split("[ \t][ \t]*", $def);

	if (@a != 3) {
		return "wrong syntax: define <name> HMUARTLGW /path/to/port|hostname";
	}

	my $name = $a[0];
	my $dev = $a[2];

	HMUARTLGW_Undefine($hash, $name);

	if (!($dev=~ m/\//)) {
		$dev .= ":2000";
		$hash->{DevType} = "LGW";
	} else {
		$dev .= "\@115200";
		$hash->{DevType} = "UART";
	}

	$hash->{DeviceName} = $dev;

	return DevIo_OpenDev($hash, 0, "HMUARTLGW_DoInit");
}

sub HMUARTLGW_Undefine($$)
{
	my ($hash, $name) = @_;
	RemoveInternalTimer($hash);
	if ($hash->{keepAlive}) {
		RemoveInternalTimer($hash->{keepAlive});
		DevIo_CloseDev($hash->{keepAlive});
		delete($attr{$hash->{keepAlive}->{NAME}});
		delete($defs{$hash->{keepAlive}->{NAME}});
		delete($hash->{keepAlive});
		$devcount--;
	}
	DevIo_CloseDev($hash);
}

sub HMUARTLGW_Reopen($;$)
{
	my ($hash, $noclose) = @_;
	$hash = $hash->{lgwHash} if ($hash->{lgwHash});
	my $name = $hash->{NAME};

	Log3($hash,1,"HMUARTLGW ${name} Reopen");

	RemoveInternalTimer($hash);
	if ($hash->{keepAlive}) {
		RemoveInternalTimer($hash->{keepAlive});
		DevIo_CloseDev($hash->{keepAlive});
		delete($attr{$hash->{keepAlive}->{NAME}});
		delete($defs{$hash->{keepAlive}->{NAME}});
		delete($hash->{keepAlive});
	}

	DevIo_CloseDev($hash) if (!$noclose);

	Log3($hash,1,"HMUARTLGW ${name} OpenDev");
	return DevIo_OpenDev($hash, 1, "HMUARTLGW_DoInit");
}

sub HMUARTLGW_Ready($)
{
	my ($hash) = @_;
	my $name = $hash->{NAME};

	if ((!$hash->{lgwHash}) && $hash->{STATE} eq "disconnected") {
		return HMUARTLGW_Reopen($hash, 1);
	}

	Log3($hash,1,"HMUARTLGW ${name} ready: ".$hash->{STATE});

	return 0;
}

#HM-LGW communicates line-based during init
sub HMUARTLGW_LGW_Init($)
{
	my ($hash) = @_;
	my $name = $hash->{NAME};

	my $p = pack("H*", $hash->{PARTIAL});

	while($p =~ m/\n/) {
		(my $line, $p) = split(/\n/, $p, 2);
		$line =~ s/\r$//;
		Log3($hash,1,"HMUARTLGW ${name} read (".length($line)."): ${line}");

		my $msg;

		if ($line =~ m/^H(..),01,([^,]*),([^,]*),([^,]*)$/) {
			$hash->{DEVCNT} = hex($1);
			$hash->{CNT} = hex($1);

			if ($hash->{DevType} eq "LGW") {
				readingsBeginUpdate($hash);
				readingsBulkUpdate($hash, "D-type", $2);
				readingsBulkUpdate($hash, "D-firmware", $3);
				readingsBulkUpdate($hash, "D-serial", $4);
				readingsEndUpdate($hash, 1);
			}
		} elsif ($line =~ m/^V(..),(................................)$/) {
			$hash->{DEVCNT} = hex($1);
			$hash->{CNT} = hex($1);

			my $lgwName = $name;
			$lgwName = $hash->{lgwHash}->{NAME} if ($hash->{lgwHash});

			my $lgwPw = AttrVal($lgwName, "lgwPw", undef);

			if ($lgwPw) {
				my($s,$us) = gettimeofday();
				my $myiv = sprintf("%04x%06x%s", $s, ($us & 0xffffff), scalar(reverse(substr($2, 14)))); #FIXME...
				my $key = Digest::MD5::md5($lgwPw);
				$hash->{crypto}{cipher} = Crypt::Rijndael->new($key, Crypt::Rijndael::MODE_ECB());
				$hash->{crypto}{encrypt}{keystream} = '';
				$hash->{crypto}{encrypt}{ciphertext} = $2;
				$hash->{crypto}{decrypt}{keystream} = '';
				$hash->{crypto}{decrypt}{ciphertext} = $myiv;

				$msg = "V%02x,${myiv}\r\n";
			} else {
				Log3($hash,1,"HMUARTLGW ${name} wants to initiate encrypted communication, but no lgwPw set!");
			}
		} elsif ($line =~ m/^S(..),([^-]*)-/) {
			$hash->{DEVCNT} = hex($1);
			$hash->{CNT} = hex($1);

			if ($2 eq "BidCoS") {
				Log3($hash,1,"HMUARTLGW ${name} BidCos-port opened");
			} elsif ($2 eq "SysCom") {
				Log3($hash,1,"HMUARTLGW ${name} KeepAlive-port opened");
			} else {
				Log3($hash,1,"HMUARTLGW ${name} Unknown protocol identification received: ${2}, reopening");
				HMUARTLGW_Reopen($hash);

				return;
			}

			$msg = ">%02x,0000\r\n";
			delete($hash->{LGW_Init});
		}

		HMUARTLGW_sendAscii($hash, $msg) if ($msg);
	}

	$hash->{PARTIAL} = unpack("H*", $p);
}

#LGW KeepAlive
sub HMUARTLGW_LGW_HandleKeepAlive($)
{
	my ($hash) = @_;
	my $name = $hash->{NAME};

	my $p = pack("H*", $hash->{PARTIAL});

	while($p =~ m/\n/) {
		(my $line, $p) = split(/\n/, $p, 2);
		$line =~ s/\r$//;
		Log3($hash,1,"HMUARTLGW ${name} read (".length($line)."): ${line}");

		my $msg;

		if ($line =~ m/^>L(..)/) {
			$hash->{DEVCNT} = hex($1);
			RemoveInternalTimer($hash);
			$hash->{DevState} = HMUARTLGW_STATE_KEEPALIVE_SENT;

			$msg = "K%02x\r\n";

			InternalTimer(gettimeofday()+1, "HMUARTLGW_CheckCmdResp", $hash, 0);
		} elsif ($line =~ m/^>K(..)/) {
			$hash->{DEVCNT} = hex($1);
			RemoveInternalTimer($hash);
			$hash->{DevState} = HMUARTLGW_STATE_RUNNING;

			my $wdTimer = 10; #now we have 15s
			InternalTimer(gettimeofday()+$wdTimer, "HMUARTLGW_SendKeepAlive", $hash, 0);
		}

		HMUARTLGW_sendAscii($hash, $msg) if ($msg);
	}

	$hash->{PARTIAL} = unpack("H*", $p);

	return;
}

sub HMUARTLGW_SendKeepAlive($)
{
	my ($hash) = @_;
	my $name = $hash->{NAME};

	RemoveInternalTimer($hash);

	$hash->{DevState} = HMUARTLGW_STATE_KEEPALIVE_SENT;
	HMUARTLGW_sendAscii($hash, "K%02x\r\n");

	InternalTimer(gettimeofday()+1, "HMUARTLGW_CheckCmdResp", $hash, 0);

	return;
}

sub HMUARTLGW_GetSetParameterReq($;$) {
	my ($hash, $value) = @_;
	my $name = $hash->{NAME};

	RemoveInternalTimer($hash);

	if ($hash->{DevState} == HMUARTLGW_STATE_SET_HMID) {
		my $hmId = AttrVal($name, "hmId", undef);

		$hmId = $value if ($value);

		HMUARTLGW_send($hash, HMUARTLGW_APP_SET_HMID . $hmId, HMUARTLGW_DST_APP);

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_GET_HMID) {
		HMUARTLGW_send($hash, HMUARTLGW_APP_GET_HMID, HMUARTLGW_DST_APP);

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_GET_DEFAULT_HMID) {
		HMUARTLGW_send($hash, HMUARTLGW_APP_DEFAULT_HMID, HMUARTLGW_DST_APP);

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_SET_TIME) {
		my $tmsg = HMUARTLGW_OS_SET_TIME;

		my $t = time();
		my @l = localtime($time);
		my $off = (timegm(@l) - timelocal(@l)) / 1800;

		$tmsg .= sprintf("%04x%02x", $t, $off);

		HMUARTLGW_send($hash, $tmsg, HMUARTLGW_DST_OS);

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_GET_PEERS) {
		HMUARTLGW_send($hash, HMUARTLGW_APP_GET_PEERS, HMUARTLGW_DST_APP);
	}

	InternalTimer(gettimeofday()+1, "HMUARTLGW_CheckCmdResp", $hash, 0);
}

sub HMUARTLGW_GetSetParameters($;$)
{
	my ($hash, $msg) = @_;
	my $name = $hash->{NAME};
	my $oldState = $hash->{DevState};
	my $hmId = AttrVal($name, "hmId", undef);
	my $ack = substr($msg, 2, 2);

	RemoveInternalTimer($hash);

	Log3($hash,1,"HMUARTLGW ${name} Ack: ${ack}") if ($ack);

	if ($ack && ($ack eq HMUARTLGW_ACK_EINPROGRESS)) {
		#Retry
		InternalTimer(gettimeofday()+0.5, "HMUARTLGW_GetSetParameterReq", $hash, 0);
		return;
	}

	if ($hash->{DevState} == HMUARTLGW_STATE_GETSET_PARAMETERS) {
		if ($hmId) {
			$hash->{DevState} = HMUARTLGW_STATE_SET_HMID;
		} else {
			$hash->{DevState} = HMUARTLGW_STATE_GET_HMID;
		}

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_SET_HMID) {
		$hash->{DevState} = HMUARTLGW_STATE_GET_HMID;

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_GET_HMID) {
		if ($ack eq HMUARTLGW_ACK_WITH_DATA) {
			readingsSingleUpdate($hash, "D-HMIdAssigned", uc(substr($msg, 8)), 1);
		}
		$hash->{DevState} = HMUARTLGW_STATE_GET_DEFAULT_HMID;

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_GET_DEFAULT_HMID) {
		if ($ack eq HMUARTLGW_ACK_WITH_DATA) {
			readingsSingleUpdate($hash, "D-HMIdOriginal", uc(substr($msg, 8)), 1);
		}
		$hash->{DevState} = HMUARTLGW_STATE_SET_TIME;

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_SET_TIME) {
		$hash->{DevState} = HMUARTLGW_STATE_GET_PEERS;

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_GET_PEERS) {
		if ($ack eq HMUARTLGW_ACK_WITH_DATA) {
		}
		$hash->{DevState} = HMUARTLGW_STATE_RUNNING;

	} else {
		$hash->{DevState} = HMUARTLGW_STATE_RUNNING;
	}

	#HM-MOD-UART doesn't seem to provide a way to read the type...
	if ($hash->{DevState} == HMUARTLGW_STATE_RUNNING && $hash->{DevType} eq "UART") {
		readingsSingleUpdate($hash, "D-type", "HM-MOD-UART", 1);
	}

	#Don't continue in state-machine if only one parameter should be
	#set/queried, SET_HMID is special, as we have to query it again
	#to update readings
	if ($hash->{OneParameterOnly} &&
	    $oldState != $hash->{DevState} &&
	    $oldState != HMUARTLGW_STATE_SET_HMID) {
		$hash->{DevState} = HMUARTLGW_STATE_RUNNING;
		delete($hash->{OneParameterOnly});
		return;
	}

	if ($hash->{DevState} != HMUARTLGW_STATE_RUNNING) {
		HMUARTLGW_GetSetParameterReq($hash);
	}
}

sub HMUARTLGW_Parse($$$)
{
	my ($hash, $msg, $dst) = @_;
	my $name = $hash->{NAME};

	$hash->{RAWMSG} = $msg;

	Log3($hash,1,"HMUARTLGW ${name} parse ${msg}, dst ${dst}");

	if ($msg =~ m/^04/ &&
	    $hash->{CNT} != $hash->{DEVCNT}) {
		Log3($hash,1,"HMUARTLGW ${name} Ack with invalid counter received, dropping");
		return;
	}

	if ($msg =~ m/^04/ &&
	    $hash->{DevState} >= HMUARTLGW_STATE_GETSET_PARAMETERS &&
	    $hash->{DevState} < HMUARTLGW_STATE_RUNNING) {
		return HMUARTLGW_GetSetParameters($hash, $msg);
	}

	if ($dst == HMUARTLGW_DST_OS) {
		if ($msg =~ m/^00(..)/) {
			if ($hash->{DevState} == HMUARTLGW_STATE_ENTER_APP) {
				my $running = pack("H*", substr($msg, 2));

				Log3($hash,1,"HMUARTLGW ${name} currently running ${running}");

				if ($running eq "Co_CPU_App") {
					$hash->{DevState} = HMUARTLGW_STATE_GETSET_PARAMETERS;
					RemoveInternalTimer($hash);
					InternalTimer(gettimeofday()+1, "HMUARTLGW_GetSetParameters", $hash, 0);
				} else {
					Log3($hash,1,"HMUARTLGW ${name} failed to enter App!");
				}
			}
		}
		if ($msg =~ m/^04(..)/) {
			my $ack = $1;

			if ($ack eq "02" && $hash->{DevState} == HMUARTLGW_STATE_QUERY_APP) {
				my $running = pack("H*", substr($msg, 4));

				Log3($hash,1,"HMUARTLGW ${name} currently running ${running}");

				if ($running eq "Co_CPU_App") {
					$hash->{DevState} = HMUARTLGW_STATE_GETSET_PARAMETERS;
					RemoveInternalTimer($hash);
					InternalTimer(gettimeofday()+1, "HMUARTLGW_GetSetParameters", $hash, 0);
				} else {
					$hash->{DevState} = HMUARTLGW_STATE_ENTER_APP;
					HMUARTLGW_send($hash, HMUARTLGW_OS_CHANGE_APP, HMUARTLGW_DST_OS);
				}
			}
		}
	} elsif ($dst == HMUARTLGW_DST_APP) {

		if ($msg =~ m/^04(..)(.*)$/) {
			my $ack = $1;
			Log3($hash,1,"HMUARTLGW ${name} Ack: ${ack} ".(($2)?$2:""));

		} elsif ($msg =~ m/^05(..)(..)(..)(.*)$/) {
			my $m = $4;
			my $rssi = 0 - hex($3);

			return if ($hash->{DevState} != HMUARTLGW_STATE_RUNNING);

			Log3($hash,1,"HMUARTLGW ${name} recv ${1} ${2} ${rssi} msg: ${m}");

			$hash->{RSSI} = $rssi;

			my $dmsg = sprintf("A%02X%s::${rssi}:${name}", length($m)/2, uc($m));
			my %addvals = (RAWMSG => $msg, RSSI => $rssi);

			Log3($hash,1,"Dispatch: ${dmsg}");
			Dispatch($hash, $dmsg, \%addvals);
		}
	}
}

sub HMUARTLGW_Read($)
{
	my ($hash) = @_;
	my $name = $hash->{NAME};

	my $buf = DevIo_SimpleRead($hash);
	return "" if (!defined($buf));

	$buf = HMUARTLGW_decrypt($hash, $buf) if ($hash->{crypto});

	my $p = pack("H*", $hash->{PARTIAL}) . $buf;
	$hash->{PARTIAL} .= unpack("H*", $buf);

	return HMUARTLGW_LGW_Init($hash) if ($hash->{LGW_Init});

	return HMUARTLGW_LGW_HandleKeepAlive($hash) if ($hash->{DevType} eq "LGW-KeepAlive");

	#need at least one frame delimiter
	return if (!($p =~ m/\xfd/));

	#garbage in the beginning?
	if (!($p =~ m/^\xfd/)) {
		$p = substr($p, index($p, chr(0xfd)));
	}

	my $unprocessed;

	while ($p =~ m/^\xfd/) {
		$unprocessed = $p;

		(undef, my $frame, $p) = split(/\xfd/, $unprocessed, 3);
		$p = chr(0xfd) . $p if ($p);

		my $unescaped;
		my $unescape_next = 0;
		foreach my $byte (split(//, $frame)) {
			if (ord($byte) == 0xfc) {
				$unescape_next = 1;
				next;
			}
			$byte |= 0x80 if ($unescape_next);
			$unescaped .= $byte;
		}

		next if (length($unescaped) < 7); #len len dst cnt cmd crc crc

		(my $len) = unpack("n", substr($unescaped, 0, 2));

		next if (length($unescaped) != $len + 4); #short packet?

		my $crc = HMUARTLGW_crc16(chr(0xfd).$unescaped);
		if ($crc != 0x0000) {
			Log3($hash, 1, "HMUARTLGW ${name} invalid checksum received, dropping packet!");
			undef($unprocessed);
			next;
		}

		Log3($hash,1,"HMUARTLGW ${name} read (".length($unescaped)."): fd".unpack("H*", $unescaped)." crc OK");

		my $dst = ord(substr($unescaped, 2, 1));
		$hash->{DEVCNT} = ord(substr($unescaped, 3, 1));

		HMUARTLGW_Parse($hash, lc(unpack("H*", substr($unescaped, 4, -2))), $dst);

		undef($unprocessed);
	}

	$hash->{PARTIAL} = unpack("H*", $unprocessed);
}

sub HMUARTLGW_Write($$$)
{
	my ($hash,$fn,$msg) = @_;
	my $name = $hash->{NAME};

	Log3($hash,1,"HMUARTLGW ${name} write: ${fn} ${msg}");

	return;
}

sub HMUARTLGW_StartInit($)
{
	my ($hash) = @_;
	my $name = $hash->{NAME};

	if ($hash->{LGW_Init}) {
		if ($hash->{LGW_Init} >= 10) {
			Log3($hash, 1, "HMUARTLGW ${name} LGW init did not complete after 10s".($hash->{crypto}?", probably wrong password":""));
			HMUARTLGW_Reopen($hash);
			return;
		}

		$hash->{LGW_Init}++;

		RemoveInternalTimer($hash);
		InternalTimer(gettimeofday()+1, "HMUARTLGW_StartInit", $hash, 0);
		return;
	}

	Log3 $hash,1,"HMUARTLGW ${name} StartInit";

	RemoveInternalTimer($hash);

	InternalTimer(gettimeofday()+1, "HMUARTLGW_CheckCmdResp", $hash, 0);

	if ($hash->{DevType} eq "LGW-KeepAlive") {
		$hash->{DevState} = HMUARTLGW_STATE_KEEPALIVE_INIT;
		HMUARTLGW_sendAscii($hash, "L%02x,02,00ff,00\r\n");
		return;
	}

	$hash->{DevState} = HMUARTLGW_STATE_QUERY_APP;
	HMUARTLGW_send($hash, HMUARTLGW_OS_GET_APP, HMUARTLGW_DST_OS);

	return;
}

sub HMUARTLGW_CheckCmdResp($)
{
	my ($hash) = @_;
	my $name = $hash->{NAME};

	RemoveInternalTimer($hash);
	if ($hash->{DevState} != HMUARTLGW_STATE_RUNNING) {
		Log3($hash, 1, "HMUARTLGW ${name} did not respond after 5s, reopening");
		HMUARTLGW_Reopen($hash);
	}

	return;
}

sub HMUARTLGW_Get($@)
{
}

sub HMUARTLGW_Set($@)
{
}

sub HMUARTLGW_Attr(@)
{
	my ($cmd, $name, $aName, $aVal) = @_;
	my $hash = $defs{$name};

	Log3($hash,1,"HMUARTLGW ${name} Attr ${cmd} ${aName} ${aVal}");

	return if (!$init_done);

	if ($aName eq "hmId") {
		if ($cmd eq "set") {
			$hash->{OneParameterOnly} = 1;
			$hash->{DevState} = HMUARTLGW_STATE_SET_HMID;
			HMUARTLGW_GetSetParameterReq($hash, $aVal);
		}
	} elsif ($aName eq "lgwPw") {
		if ($hash->{DevType} eq "LGW") {
			HMUARTLGW_Reopen($hash);
		}
	}

	return;
}

sub HMUARTLGW_send($$$)
{
	my ($hash, $msg, $dst) = @_;
	my $name = $hash->{NAME};

	Log3($hash,1,"HMUARTLGW ${name} encode ${msg}, dst ${dst}");

	$hash->{CNT} = ($hash->{CNT} + 1) & 0xff;

	my $frame = pack("cnccH*", 0xfd,
	                            (length($msg) / 2) + 2,
	                            $dst,
	                            $hash->{CNT},
	                            $msg);

	$frame .= pack("n", HMUARTLGW_crc16($frame));

	HMUARTLGW_send_frame($hash, $frame);
}

sub HMUARTLGW_send_frame($$)
{
	my ($hash, $frame) = @_;
	my $name = $hash->{NAME};

	Log3($hash,1,"HMUARTLGW ${name} send (".length($frame)."): ".unpack("H*", $frame));

	my $escaped = substr($frame, 0, 1);

	foreach my $byte (split(//, substr($frame, 1))) {
		if (ord($byte) != 0xfc && ord($byte) != 0xfd) {
			$escaped .= $byte;
			next;
		}
		$escaped .= chr(0xfc);
		$escaped .= chr(ord($byte) & 0x7f);
	}

	$escaped = HMUARTLGW_encrypt($hash, $escaped) if ($hash->{crypto});

	DevIo_SimpleWrite($hash, $escaped, 0);
}

sub HMUARTLGW_sendAscii($$)
{
	my ($hash, $msg) = @_;
	my $name = $hash->{NAME};

	$msg = sprintf($msg, $hash->{CNT});

	Log3($hash,1,"HMUARTLGW ${name} send (".length($msg)."): ". $msg =~ s/\r\n//r);
	$msg = HMUARTLGW_encrypt($hash, $msg) if ($hash->{crypto} && !($msg =~ m/^V/));

	$hash->{CNT} = ($hash->{CNT} + 1) & 0xff;

	DevIo_SimpleWrite($hash, $msg, 2);
}

sub HMUARTLGW_crc16($)
{
	my ($msg) = @_;
	my $crc = 0xd77f;

	foreach my $byte (split(//, $msg)) {
		$crc ^= (ord($byte) << 8) & 0xff00;
		for (my $i = 0; $i < 8; $i++) {
			if ($crc & 0x8000) {
				$crc = ($crc << 1) & 0xffff;
				$crc ^= 0x8005;
			} else {
				$crc = ($crc << 1) & 0xffff;
			}
		}
	}

	return $crc;
}

sub HMUARTLGW_encrypt($$)
{
	my ($hash, $plaintext) = @_;
	my $ciphertext = '';

	my $ks = pack("H*", $hash->{crypto}{encrypt}{keystream});
	my $ct = pack("H*", $hash->{crypto}{encrypt}{ciphertext});

	while($plaintext) {
		if($ks) {
			my $len = length($plaintext);

			if (length($ks) < $len) {
				$len = length($ks);
			}

			my $ppart = substr($plaintext, 0, $len);
			my $kpart = substr($ks, 0, $len);

			$plaintext = substr($plaintext, $len);
			$ks = substr($ks, $len);

			$ct .= $ppart ^ $kpart;

			$ciphertext .= $ppart ^ $kpart;
		} else {
			Log3($hash,1,"HMUARTLGW ${name} invalid ciphertext len: ".length($ct)) if (length($ct) != 16);
			$ks = $hash->{crypto}{cipher}->encrypt($ct);
			$ct='';
		}
	}

	$hash->{crypto}{encrypt}{keystream} = unpack("H*", $ks);
	$hash->{crypto}{encrypt}{ciphertext} = unpack("H*", $ct);

	$ciphertext;
}

sub HMUARTLGW_decrypt($$)
{
        my ($hash, $ciphertext) = @_;
        my $plaintext = '';

	my $ks = pack("H*", $hash->{crypto}{decrypt}{keystream});
	my $ct = pack("H*", $hash->{crypto}{decrypt}{ciphertext});

        while($ciphertext) {
                if($ks) {
                        my $len = length($ciphertext);

                        if (length($ks) < $len) {
                                $len = length($ks);
                        }

                        my $cpart = substr($ciphertext, 0, $len);
                        my $kpart = substr($ks, 0, $len);

                        $ciphertext = substr($ciphertext, $len);
                        $ks = substr($ks, $len);

                        $ct .= $cpart;

                        $plaintext .= $cpart ^ $kpart;
                } else {
			Log3($hash,1,"HMUARTLGW ${name} invalid ciphertext len: ".length($ct)) if (length($ct) != 16);
                        $ks = $hash->{crypto}{cipher}->encrypt($ct);
                        $ct='';
                }
        }

	$hash->{crypto}{decrypt}{keystream} = unpack("H*", $ks);
	$hash->{crypto}{decrypt}{ciphertext} = unpack("H*", $ct);

        $plaintext;
}

1;
