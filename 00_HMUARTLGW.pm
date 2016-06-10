##############################################
# $Id$
package main;

use strict;
use warnings;

use Digest::MD5;
use Time::HiRes qw(gettimeofday time);
use Time::Local;
eval "use Crypt::Rijndael";
my $cryptFunc = ($@)?0:1;

use constant {
	HMUARTLGW_OS_GET_APP               => "00",
	HMUARTLGW_OS_GET_FIRMWARE          => "02",
	HMUARTLGW_OS_CHANGE_APP            => "03",
	HMUARTLGW_OS_ACK                   => "04",
	HMUARTLGW_OS_UPDATE_FIRMWARE       => "05",
	HMUARTLGW_OS_UNSOL_CREDITS         => "05",
	HMUARTLGW_OS_NORMAL_MODE           => "06",
	HMUARTLGW_OS_UPDATE_MODE           => "07",
	HMUARTLGW_OS_GET_CREDITS           => "08",
	HMUARTLGW_OS_ENABLE_CREDITS        => "09",
	HMUARTLGW_OS_ENABLE_CSMACA         => "0A",
	HMUARTLGW_OS_GET_SERIAL            => "0B",
	HMUARTLGW_OS_SET_TIME              => "0E",

	HMUARTLGW_APP_SET_HMID             => "00",
	HMUARTLGW_APP_GET_HMID             => "01",
	HMUARTLGW_APP_SEND                 => "02",
	HMUARTLGW_APP_SET_CURRENT_KEY      => "03", #key index, 00x17 when no key
	HMUARTLGW_APP_ACK                  => "04",
	HMUARTLGW_APP_RECV                 => "05",
	HMUARTLGW_APP_ADD_PEER             => "06",
	HMUARTLGW_APP_REMOVE_PEER          => "07",
	HMUARTLGW_APP_GET_PEERS            => "08",
	HMUARTLGW_APP_PEER_ADD_AES         => "09",
	HMUARTLGW_APP_PEER_REMOVE_AES      => "0A",
	HMUARTLGW_APP_SET_TEMP_KEY         => "0B", #key index, 00x17 when no key
	HMUARTLGW_APP_SET_PREVIOUS_KEY     => "0F", #key index, 00x17 when no key
	HMUARTLGW_APP_DEFAULT_HMID         => "10",

	HMUARTLGW_ACK_NACK                 => "00",
	HMUARTLGW_ACK                      => "01",
	HMUARTLGW_ACK_WITH_RESPONSE        => "03",
	HMUARTLGW_ACK_EUNKNOWN             => "04",
	HMUARTLGW_ACK_ENOCREDITS           => "05",
	HMUARTLGW_ACK_ECSMACA              => "06",
	HMUARTLGW_ACK_WITH_DATA            => "07",
	HMUARTLGW_ACK_EINPROGRESS          => "08",
	HMUARTLGW_ACK_WITH_RESPONSE_AES_OK => "0C",
	HMUARTLGW_ACK_WITH_RESPONSE_AES_KO => "0D",
	HMUARTLGW_RECV_RESP                => "01",
	HMUARTLGW_RECV_RESP_WITH_AES_OK    => "02",
	HMUARTLGW_RECV_RESP_WITH_AES_KO    => "03",
	HMUARTLGW_RECV_TRIG                => "11",
	HMUARTLGW_RECV_TRIG_WITH_AES_OK    => "12",

        HMUARTLGW_DST_OS                   => 0,
        HMUARTLGW_DST_APP                  => 1,

	HMUARTLGW_STATE_NONE               => 0,
	HMUARTLGW_STATE_QUERY_APP          => 1,
	HMUARTLGW_STATE_ENTER_APP          => 2,
	HMUARTLGW_STATE_GETSET_PARAMETERS  => 3,
	HMUARTLGW_STATE_SET_TIME           => 4,
	HMUARTLGW_STATE_SET_HMID           => 5,
	HMUARTLGW_STATE_GET_HMID           => 6,
	HMUARTLGW_STATE_GET_DEFAULT_HMID   => 7,
	HMUARTLGW_STATE_GET_PEERS          => 8,
	HMUARTLGW_STATE_GET_FIRMWARE       => 9,
	HMUARTLGW_STATE_ENABLE_CSMACA      => 10,
	HMUARTLGW_STATE_ENABLE_CREDITS     => 11,
	HMUARTLGW_STATE_CLEAR_PEERS        => 12,
	HMUARTLGW_STATE_CLEAR_PEERS_AES    => 13,
	HMUARTLGW_STATE_GET_SERIAL         => 14,
	HMUARTLGW_STATE_SET_CURRENT_KEY    => 15,
	HMUARTLGW_STATE_SET_PREVIOUS_KEY   => 16,
	HMUARTLGW_STATE_SET_TEMP_KEY       => 17,
	HMUARTLGW_STATE_UPDATE_PEER        => 90,
	HMUARTLGW_STATE_UPDATE_PEER_AES1   => 91,
	HMUARTLGW_STATE_UPDATE_PEER_AES2   => 92,
	HMUARTLGW_STATE_UPDATE_PEER_CFG    => 93,
	HMUARTLGW_STATE_KEEPALIVE_INIT     => 96,
	HMUARTLGW_STATE_KEEPALIVE_SENT     => 97,
	HMUARTLGW_STATE_GET_CREDITS        => 98,
	HMUARTLGW_STATE_RUNNING            => 99,
	HMUARTLGW_STATE_SEND               => 100,
};

my %sets = (
	"hmPairForSec" => "HomeMatic",
	"hmPairSerial" => "HomeMatic",
	"reopen"       => "",
);

my %gets = (
);

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

	$hash->{AttrList}= "hmId " .
	                   "lgwPw " .
	                   "hmKey hmKey2 hmKey3 " .
			   "dutyCycle:1,0 " .
			   "CSMA/CA:1,0 " .
	                   $readingFnAttributes;
}

sub HMUARTLGW_SendPendingCmd($);
sub HMUARTLGW_getAesKeys($);
sub HMUARTLGW_updateMsgLoad($$);
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
	delete($hash->{Helper});
	delete($hash->{AssignedPeerCnt});
	delete($hash->{msgLoadCurrent});
	delete($hash->{FW});
	delete($hash->{owner});
	$hash->{DevState} = HMUARTLGW_STATE_NONE;
	$hash->{XmitOpen} = 0;

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
		my ($ip, $port) = split(/:/, $hash->{DeviceName});
		$keepAlive->{DeviceName} = "${ip}:" . ($port + 1);
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

	if ($dev !~ m/\//) {
		$dev .= ":2000" if ($dev !~ m/:/);
		$hash->{DevType} = "LGW";
	} else {
		$dev .= "\@115200" if ($dev !~ m/\@/);
		$hash->{DevType} = "UART";
		readingsBeginUpdate($hash);
		delete($hash->{READINGS}{"D-LANfirmware"});
		readingsBulkUpdate($hash, "D-type", "HM-MOD-UART");
		readingsEndUpdate($hash, 1);
	}

	$hash->{DeviceName} = $dev;

	return DevIo_OpenDev($hash, 0, "HMUARTLGW_DoInit");
}

sub HMUARTLGW_Undefine($$;$)
{
	my ($hash, $name, $noclose) = @_;

	RemoveInternalTimer($hash);
	RemoveInternalTimer("HMUARTLGW_CheckCredits:$name");
	if ($hash->{keepAlive}) {
		RemoveInternalTimer($hash->{keepAlive});
		DevIo_CloseDev($hash->{keepAlive});
		delete($attr{$hash->{keepAlive}->{NAME}});
		delete($defs{$hash->{keepAlive}->{NAME}});
		delete($hash->{keepAlive});
		$devcount--;
	}

	DevIo_CloseDev($hash) if (!$noclose);
}

sub HMUARTLGW_Reopen($;$)
{
	my ($hash, $noclose) = @_;
	$hash = $hash->{lgwHash} if ($hash->{lgwHash});
	my $name = $hash->{NAME};

	Log3($hash,1,"HMUARTLGW ${name} Reopen");

	HMUARTLGW_Undefine($hash, $name, $noclose);

	return DevIo_OpenDev($hash, 1, "HMUARTLGW_DoInit");
}

sub HMUARTLGW_Ready($)
{
	my ($hash) = @_;
	my $name = $hash->{NAME};

	Log3($hash,1,"HMUARTLGW ${name} ready: ".$hash->{STATE});

	if ((!$hash->{lgwHash}) && $hash->{STATE} eq "disconnected") {
		return HMUARTLGW_Reopen($hash, 1);
	}

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
		Log3($hash, 4, "HMUARTLGW ${name} read (".length($line)."): ${line}");

		my $msg;

		if ($line =~ m/^H(..),01,([^,]*),([^,]*),([^,]*)$/) {
			$hash->{DEVCNT} = hex($1);
			$hash->{CNT} = hex($1);

			if ($hash->{DevType} eq "LGW") {
				readingsBeginUpdate($hash);
				readingsBulkUpdate($hash, "D-type", $2);
				readingsBulkUpdate($hash, "D-LANfirmware", $3);
				readingsBulkUpdate($hash, "D-serialNr", $4);
				readingsEndUpdate($hash, 1);
			}
		} elsif ($line =~ m/^V(..),(................................)$/) {
			$hash->{DEVCNT} = hex($1);
			$hash->{CNT} = hex($1);

			my $lgwName = $name;
			$lgwName = $hash->{lgwHash}->{NAME} if ($hash->{lgwHash});

			my $lgwPw = AttrVal($lgwName, "lgwPw", undef);

			if (!$cryptFunc) {
				Log3($hash, 1, "HMUARTLGW ${name} wants to initiate encrypted communication, but Crypt::Rijndael is not installed.");
			} elsif (!$lgwPw) {
				Log3($hash, 1, "HMUARTLGW ${name} wants to initiate encrypted communication, but no lgwPw set!");
			} else {
				my($s,$us) = gettimeofday();
				my $myiv = sprintf("%04x%06x%s", $s, ($us & 0xffffff), scalar(reverse(substr($2, 14)))); #FIXME...
				my $key = Digest::MD5::md5($lgwPw);
				$hash->{crypto}{cipher} = Crypt::Rijndael->new($key, Crypt::Rijndael::MODE_ECB());
				$hash->{crypto}{encrypt}{keystream} = '';
				$hash->{crypto}{encrypt}{ciphertext} = $2;
				$hash->{crypto}{decrypt}{keystream} = '';
				$hash->{crypto}{decrypt}{ciphertext} = $myiv;

				$msg = "V%02x,${myiv}\r\n";
			}
		} elsif ($line =~ m/^S(..),([^-]*)-/) {
			$hash->{DEVCNT} = hex($1);
			$hash->{CNT} = hex($1);

			if ($2 eq "BidCoS") {
				Log3($hash, 3, "HMUARTLGW ${name} BidCoS-port opened");
			} elsif ($2 eq "SysCom") {
				Log3($hash, 3, "HMUARTLGW ${name} KeepAlive-port opened");
			} else {
				Log3($hash, 1, "HMUARTLGW ${name} Unknown port identification received: ${2}, reopening");
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
		Log3($hash, 4, "HMUARTLGW ${name} read (".length($line)."): ${line}");

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

sub HMUARTLGW_CheckCredits($)
{
	my ($in) = shift;
	my (undef, $name) = split(':',$in);
	my $hash = $defs{$name};

	my $next = 15;

	if ($hash->{DevState} == HMUARTLGW_STATE_RUNNING) {
		Log3($hash, 5, "HMUARTLGW ${name} checking credits (from timer)");
		$hash->{Helper}{OneParameterOnly} = 1;
		$hash->{DevState} = HMUARTLGW_STATE_GET_CREDITS;
		HMUARTLGW_GetSetParameterReq($hash);
	} else {
		$next = 1;
	}
	RemoveInternalTimer("HMUARTLGW_CheckCredits:$name");
	InternalTimer(gettimeofday()+$next, "HMUARTLGW_CheckCredits", "HMUARTLGW_CheckCredits:$name", 1);
}

sub HMUARTLGW_SendPendingCmd($)
{
	my ($hash) = @_;
	my $name = $hash->{NAME};

	if ($hash->{DevState} == HMUARTLGW_STATE_RUNNING &&
	    @{$hash->{Helper}{PendingCMD}}) {
		my $cmd = $hash->{Helper}{PendingCMD}->[0];

		if ($cmd eq "AESkeys") {
			Log3($hash, 5, "HMUARTLGW ${name} setting keys");
			$hash->{Helper}{OneParameterOnly} = 1;
			$hash->{DevState} = HMUARTLGW_STATE_SET_CURRENT_KEY;
			HMUARTLGW_GetSetParameterReq($hash);
			shift(@{$hash->{Helper}{PendingCMD}}); #retry will be handled by GetSetParameter
		} elsif ($cmd eq "Credits") {
			Log3($hash, 5, "HMUARTLGW ${name} checking credits (from send)");
			$hash->{Helper}{OneParameterOnly} = 1;
			$hash->{DevState} = HMUARTLGW_STATE_GET_CREDITS;
			HMUARTLGW_GetSetParameterReq($hash);
			shift(@{$hash->{Helper}{PendingCMD}}); #retry will be handled by GetSetParameter
		} else {
			#try for 3s, packet was not sent wirelessly yet!
			if (defined($hash->{Helper}{RetryCnt}) && $hash->{Helper}{RetryCnt} >= 30) {
				Log3($hash, 1, "HMUARTLGW ${name} resend failed too often, dropping packet");
				shift(@{$hash->{Helper}{PendingCMD}});
				delete($hash->{Helper}{RetryCnt});
				#try next command
				return HMUARTLGW_SendPendingCmd($hash);
			} elsif ($hash->{Helper}{RetryCnt}) {
				Log3($hash, 5, "HMUARTLGW ${name} Retry: ".$hash->{Helper}{RetryCnt});
			}

			$hash->{DevState} = HMUARTLGW_STATE_SEND;
			HMUARTLGW_send($hash, $cmd, HMUARTLGW_DST_APP);
			RemoveInternalTimer($hash);
			InternalTimer(gettimeofday()+10, "HMUARTLGW_CheckCmdResp", $hash, 0);
		}
	}
}

sub HMUARTLGW_UpdatePeerReq($;$) {
	my ($hash, $peer) = @_;
	my $name = $hash->{NAME};

	$peer = $hash->{Helper}{UpdatePeer} if (!$peer);

	Log3($hash, 4, "HMUARTLGW ${name} UpdatePeerReq: ".$peer->{id}.", state ".$hash->{DevState});

	my $msg;

	if ($hash->{DevState} == HMUARTLGW_STATE_UPDATE_PEER) {
		if ($peer->{operation} eq "-") {
			$msg = HMUARTLGW_APP_REMOVE_PEER . $peer->{id};
		} else {
			my $flags = hex($peer->{flags});

			$msg = HMUARTLGW_APP_ADD_PEER .
			       $peer->{id} .
			       $peer->{kNo} .
			       (($flags & 0x01) ? "01" : "00") . #AES
			       (($flags & 0x02) ? "01" : "00");  #Wakeup
		}

		$hash->{Helper}{UpdatePeer} = $peer;

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_UPDATE_PEER_AES1) {
		$msg = HMUARTLGW_APP_PEER_REMOVE_AES . $hash->{Helper}{UpdatePeer}{id};
		for (my $chan = 0; $chan < 60; $chan++) {
			$msg .= sprintf("%02x", $chan);
		}

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_UPDATE_PEER_AES2) {
		$msg = HMUARTLGW_APP_PEER_ADD_AES . $peer->{id};

		if ($peer->{operation} eq "+") {
			my $aesChannels = hex(join("",reverse(unpack "(A2)*", $peer->{aesChannels})));
			Log3($hash,1,"HMUARTLGW ${name} AESchannels: " . sprintf("%08x", $aesChannels));
			for (my $chan = 0; $chan < 60; $chan++) {
				if ($aesChannels & (1 << $chan)) {
					Log3($hash,1,"HMUARTLGW ${name} Enabling AES for channel ${chan}");
					$msg .= sprintf("%02x", $chan)
				}
			}
		}

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_UPDATE_PEER_CFG) {
		$msg = HMUARTLGW_APP_GET_PEERS;
	}

	if ($msg) {
		HMUARTLGW_send($hash, $msg, HMUARTLGW_DST_APP);
		RemoveInternalTimer($hash);
		InternalTimer(gettimeofday()+1, "HMUARTLGW_CheckCmdResp", $hash, 0);
	}
}

sub HMUARTLGW_UpdatePeer($$) {
	my ($hash, $peer) = @_;

	if ($hash->{DevState} == HMUARTLGW_STATE_RUNNING) {
		$hash->{DevState} = HMUARTLGW_STATE_UPDATE_PEER;
		HMUARTLGW_UpdatePeerReq($hash, $peer);
	} else {
		#enqueue for next update
		push @{$hash->{Helper}{PeerQueue}}, $peer;
	}
}

sub HMUARTLGW_UpdateQueuedPeer($) {
	my ($hash) = @_;

	if ($hash->{DevState} == HMUARTLGW_STATE_RUNNING &&
	    @{$hash->{Helper}{PeerQueue}}) {
		return HMUARTLGW_UpdatePeer($hash, shift(@{$hash->{Helper}{PeerQueue}}));
	}
}

sub HMUARTLGW_ParsePeers($$) {
	my ($hash, $msg) = @_;

	my $peers = substr($msg, 8);
	$hash->{AssignedPeerCnt} = 0;
	delete($hash->{Helper}{AssignedPeers});
	while($peers) {
		my $id = substr($peers, 0, 6, '');
		my $aesChannels = substr($peers, 0, 16, '');
		my $kNo= hex(substr($peers, 0, 2, ''));
		Log3($hash,1,"HMUARTLGW $hash->{NAME} known peer: ${id}, aesChannels: ${aesChannels}, kNo: ${kNo}");

		$hash->{Helper}{AssignedPeers}{$id} = "$aesChannels (kNo: ${kNo})";
		$hash->{AssignedPeerCnt}++;
	}
}

sub HMUARTLGW_GetSetParameterReq($;$) {
	my ($hash, $value) = @_;
	my $name = $hash->{NAME};

	RemoveInternalTimer($hash);

	if ($hash->{DevState} == HMUARTLGW_STATE_SET_HMID) {
		my $hmId = AttrVal($name, "hmId", undef);

		$hmId = $value if (defined($value));

		HMUARTLGW_send($hash, HMUARTLGW_APP_SET_HMID . $hmId, HMUARTLGW_DST_APP);

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_GET_HMID) {
		HMUARTLGW_send($hash, HMUARTLGW_APP_GET_HMID, HMUARTLGW_DST_APP);

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_GET_DEFAULT_HMID) {
		HMUARTLGW_send($hash, HMUARTLGW_APP_DEFAULT_HMID, HMUARTLGW_DST_APP);

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_SET_TIME) {
		my $tmsg = HMUARTLGW_OS_SET_TIME;

		my $t = time();
		my @l = localtime($t);
		my $off = (timegm(@l) - timelocal(@l)) / 3600;

		$tmsg .= sprintf("%04x%02x", $t, $off);

		HMUARTLGW_send($hash, $tmsg, HMUARTLGW_DST_OS);

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_GET_FIRMWARE) {
		HMUARTLGW_send($hash, HMUARTLGW_OS_GET_FIRMWARE, HMUARTLGW_DST_OS);

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_GET_SERIAL) {
		HMUARTLGW_send($hash, HMUARTLGW_OS_GET_SERIAL, HMUARTLGW_DST_OS);

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_ENABLE_CSMACA) {
		my $csma_ca = AttrVal($name, "CSMA/CA", 1);

		$csma_ca = $value if (defined($value));

		HMUARTLGW_send($hash, HMUARTLGW_OS_ENABLE_CSMACA . sprintf("%02x", $csma_ca), HMUARTLGW_DST_OS);

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_ENABLE_CREDITS) {
		my $dutyCycle = AttrVal($name, "dutyCycle", 1);

		$dutyCycle = $value if (defined($value));

		HMUARTLGW_send($hash, HMUARTLGW_OS_ENABLE_CREDITS . sprintf("%02x", $dutyCycle), HMUARTLGW_DST_OS);

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_SET_CURRENT_KEY) {
		#current key is key with highest idx
		@{$hash->{Helper}{AESKeyQueue}} = HMUARTLGW_getAesKeys($hash);
		my $key = shift(@{$hash->{Helper}{AESKeyQueue}});
		HMUARTLGW_send($hash, HMUARTLGW_APP_SET_CURRENT_KEY . ($key?$key:"00"x17), HMUARTLGW_DST_APP);

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_SET_PREVIOUS_KEY) {
		#previous key has second highest index
		my $key = shift(@{$hash->{Helper}{AESKeyQueue}});
		HMUARTLGW_send($hash, HMUARTLGW_APP_SET_PREVIOUS_KEY . ($key?$key:"00"x17), HMUARTLGW_DST_APP);

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_SET_TEMP_KEY) {
		#temp key has third highest index
		my $key = shift(@{$hash->{Helper}{AESKeyQueue}});
		delete($hash->{Helper}{AESKeyQueue});
		HMUARTLGW_send($hash, HMUARTLGW_APP_SET_TEMP_KEY . ($key?$key:"00"x17), HMUARTLGW_DST_APP);

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_GET_PEERS) {
		HMUARTLGW_send($hash, HMUARTLGW_APP_GET_PEERS, HMUARTLGW_DST_APP);

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_CLEAR_PEERS) {
		my $peer = (keys(%{$hash->{Helper}{AssignedPeers}}))[0];
		$hash->{Helper}{RemovePeer} = $peer;
		HMUARTLGW_send($hash, HMUARTLGW_APP_REMOVE_PEER . $peer, HMUARTLGW_DST_APP);

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_CLEAR_PEERS_AES) {
		my $msg = HMUARTLGW_APP_PEER_REMOVE_AES . $hash->{Helper}{RemovePeer};
		for (my $chan = 0; $chan < 60; $chan++) {
			$msg .= sprintf("%02x", $chan);
		}

		HMUARTLGW_send($hash, $msg, HMUARTLGW_DST_APP);

	} elsif ($hash->{DevState} >= HMUARTLGW_STATE_UPDATE_PEER &&
	         $hash->{DevState} <= HMUARTLGW_STATE_UPDATE_PEER_CFG) {
		HMUARTLGW_UpdatePeerReq($hash);
		return;

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_GET_CREDITS) {
		HMUARTLGW_send($hash, HMUARTLGW_OS_GET_CREDITS, HMUARTLGW_DST_OS);

	} else {
		return;
	}

	InternalTimer(gettimeofday()+1, "HMUARTLGW_CheckCmdResp", $hash, 0);
}

sub HMUARTLGW_GetSetParameters($;$)
{
	my ($hash, $msg) = @_;
	my $name = $hash->{NAME};
	my $oldState = $hash->{DevState};
	my $hmId = AttrVal($name, "hmId", undef);
	my $ack = substr($msg, 2, 2) if ($msg);

	RemoveInternalTimer($hash);

	Log3($hash,1,"HMUARTLGW ${name} GetSet Ack: ${ack}, State: ".$hash->{DevState}) if ($ack);

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
			$hash->{owner} = uc(substr($msg, 8));
		}
		$hash->{DevState} = HMUARTLGW_STATE_GET_DEFAULT_HMID;

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_GET_DEFAULT_HMID) {
		if ($ack eq HMUARTLGW_ACK_WITH_DATA) {
			readingsSingleUpdate($hash, "D-HMIdOriginal", uc(substr($msg, 8)), 1);
		}
		$hash->{DevState} = HMUARTLGW_STATE_SET_TIME;

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_SET_TIME) {
		$hash->{DevState} = HMUARTLGW_STATE_GET_FIRMWARE;

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_GET_FIRMWARE) {
		if ($ack eq "02") { #?
			my $fw = hex(substr($msg, 10, 2)).".".
			         hex(substr($msg, 12, 2)).".".
			         hex(substr($msg, 14, 2));
			$hash->{FW} = hex((substr($msg, 10, 6)));
			readingsSingleUpdate($hash, "D-firmware", $fw, 1);
		}
		$hash->{DevState} = HMUARTLGW_STATE_GET_SERIAL;

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_GET_SERIAL) {
		if ($ack eq "02" && $hash->{DevType} eq "UART") { #?
			readingsSingleUpdate($hash, "D-serialNr", pack("H*", substr($msg, 4)), 1);
		}
		$hash->{DevState} = HMUARTLGW_STATE_ENABLE_CSMACA;

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_ENABLE_CSMACA) {
		$hash->{DevState} = HMUARTLGW_STATE_ENABLE_CREDITS;

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_ENABLE_CREDITS) {
		$hash->{DevState} = HMUARTLGW_STATE_SET_CURRENT_KEY;

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_SET_CURRENT_KEY) {
		$hash->{DevState} = HMUARTLGW_STATE_SET_PREVIOUS_KEY;

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_SET_PREVIOUS_KEY) {
		$hash->{DevState} = HMUARTLGW_STATE_SET_TEMP_KEY;

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_SET_TEMP_KEY) {
		$hash->{DevState} = HMUARTLGW_STATE_GET_PEERS;

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_GET_PEERS) {
		if ($ack eq HMUARTLGW_ACK_WITH_DATA) {
			HMUARTLGW_ParsePeers($hash, $msg);
		}
		if (%{$hash->{Helper}{AssignedPeers}}) {
			$hash->{DevState} = HMUARTLGW_STATE_CLEAR_PEERS;
		} else {
			delete($hash->{Helper}{AssignedPeers});
			$hash->{DevState} = HMUARTLGW_STATE_RUNNING;
		}

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_CLEAR_PEERS) {
		if ($ack eq HMUARTLGW_ACK_WITH_DATA) {
			#040701010001
			$hash->{AssignedPeerCnt} = hex(substr($msg, 8, 4));
		}
		$hash->{DevState} = HMUARTLGW_STATE_CLEAR_PEERS_AES;

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_CLEAR_PEERS_AES) {

		delete($hash->{Helper}{AssignedPeers}{$hash->{Helper}{RemovePeer}});
		delete($hash->{Helper}{RemovePeer});

		if (%{$hash->{Helper}{AssignedPeers}}) {
			$hash->{DevState} = HMUARTLGW_STATE_CLEAR_PEERS
		} else {
			delete($hash->{Helper}{AssignedPeers});
			$hash->{DevState} = HMUARTLGW_STATE_RUNNING
		}
	} elsif ($hash->{DevState} == HMUARTLGW_STATE_GET_CREDITS) {
		if ($ack eq "02") { #?
			HMUARTLGW_updateMsgLoad($hash, hex(substr($msg, 4)));
		}
		$hash->{DevState} = HMUARTLGW_STATE_RUNNING;
	}

	if ($hash->{DevState} == HMUARTLGW_STATE_RUNNING &&
	    $oldState != HMUARTLGW_STATE_RUNNING &&
	    (!$hash->{Helper}{OneParameterOnly})) {
		#Init sequence over, add known peers
		foreach my $peer (keys(%{$hash->{Peers}})) {
			if ($modules{CUL_HM}{defptr}{$peer} &&
			    $modules{CUL_HM}{defptr}{$peer}{helper}{io}{newChn}) {
				my ($id, $flags, $kNo, $aesChannels) = split(/,/, $modules{CUL_HM}{defptr}{$peer}{helper}{io}{newChn});
				my $p = {
					id => substr($id, 1),
					operation => substr($id, 0, 1),
					flags => $flags,
					kNo => $kNo,
					aesChannels => $aesChannels,
				};
				#enqueue for later
				if ($p->{operation} eq "+") {
					$hash->{Peers}{$peer} = "pending";
					push @{$hash->{Helper}{PeerQueue}}, $p;
				} else {
					delete($hash->{Peers}{$peer});
				}
			} else {
				delete($hash->{Peers}{$peer});
			}
		}

		#start credit checker
		RemoveInternalTimer("HMUARTLGW_CheckCredits:$name");
		InternalTimer(gettimeofday()+1, "HMUARTLGW_CheckCredits", "HMUARTLGW_CheckCredits:$name", 1);

		$hash->{Helper}{Initialized} = 1;
	}

	if ($hash->{DevState} == HMUARTLGW_STATE_UPDATE_PEER) {
		if ($ack eq HMUARTLGW_ACK_WITH_DATA) {
			#040701010002fffffffffffffff9
			$hash->{AssignedPeerCnt} = hex(substr($msg, 8, 4));
			$hash->{Helper}{AssignedPeers}{$hash->{Helper}{UpdatePeer}->{id}} = substr($msg, 12);
		}
		$hash->{DevState} = HMUARTLGW_STATE_UPDATE_PEER_AES1;

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_UPDATE_PEER_AES1) {
		$hash->{DevState} = HMUARTLGW_STATE_UPDATE_PEER_AES2;

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_UPDATE_PEER_AES2) {
		$hash->{Peers}{$hash->{Helper}{UpdatePeer}->{id}} = "assigned";
		if (@{$hash->{Helper}{PeerQueue}}) {
			#Still peers in queue, get current assigned peers
			#only when queue is empty
			$hash->{DevState} = HMUARTLGW_STATE_RUNNING;
		} else {
			$hash->{DevState} = HMUARTLGW_STATE_UPDATE_PEER_CFG;
		}

	} elsif ($hash->{DevState} == HMUARTLGW_STATE_UPDATE_PEER_CFG) {
		if ($ack eq HMUARTLGW_ACK_WITH_DATA) {
			HMUARTLGW_ParsePeers($hash, $msg);
		}

		delete($hash->{Helper}{UpdatePeer});

		$hash->{DevState} = HMUARTLGW_STATE_RUNNING;
	}

	#Don't continue in state-machine if only one parameter should be
	#set/queried, SET_HMID is special, as we have to query it again
	#to update readings. SET_CURRENT_KEY is always followed by
	#SET_PREVIOUS_KEY and SET_TEMP_KEY.
	if ($hash->{Helper}{OneParameterOnly} &&
	    $oldState != $hash->{DevState} &&
	    $oldState != HMUARTLGW_STATE_SET_HMID &&
	    $oldState != HMUARTLGW_STATE_SET_CURRENT_KEY &&
	    $oldState != HMUARTLGW_STATE_SET_PREVIOUS_KEY) {
		$hash->{DevState} = HMUARTLGW_STATE_RUNNING;
		delete($hash->{Helper}{OneParameterOnly});
	}

	if ($hash->{DevState} != HMUARTLGW_STATE_RUNNING) {
		HMUARTLGW_GetSetParameterReq($hash);
	} else {
		HMUARTLGW_UpdateQueuedPeer($hash);
		HMUARTLGW_SendPendingCmd($hash);
	}
}

sub HMUARTLGW_Parse($$$)
{
	my ($hash, $msg, $dst) = @_;
	my $name = $hash->{NAME};

	my $recv;
	my $CULinfo = '';

	$hash->{RAWMSG} = $msg;

	Log3($hash, 1, "HMUARTLGW ${name} recv: ".sprintf("%02X", $dst)." ${msg}, state ".$hash->{DevState})
	     if ($msg !~ m/^05/ && $msg !~ m/^040[3C]/);

	if ($msg =~ m/^04/ &&
	    $hash->{CNT} != $hash->{DEVCNT}) {
		Log3($hash, 1 ,"HMUARTLGW ${name} Ack with invalid counter received, dropping");
		return;
	}

	if ($msg =~ m/^04/ &&
	    $hash->{DevState} >= HMUARTLGW_STATE_GETSET_PARAMETERS &&
	    $hash->{DevState} < HMUARTLGW_STATE_RUNNING) {
		HMUARTLGW_GetSetParameters($hash, $msg);
		return;
	}

	if ($dst == HMUARTLGW_DST_OS) {
		if ($msg =~ m/^00(..)/) {
			my $running = pack("H*", substr($msg, 2));

			if ($hash->{DevState} == HMUARTLGW_STATE_ENTER_APP) {
				Log3($hash,1,"HMUARTLGW ${name} currently running ${running}");

				if ($running eq "Co_CPU_App") {
					$hash->{DevState} = HMUARTLGW_STATE_GETSET_PARAMETERS;
					RemoveInternalTimer($hash);
					InternalTimer(gettimeofday()+1, "HMUARTLGW_GetSetParameters", $hash, 0);
				} else {
					Log3($hash,1,"HMUARTLGW ${name} failed to enter App!");
				}
			} elsif ($hash->{DevState} > HMUARTLGW_STATE_ENTER_APP) {
				Log3($hash,1,"HMUARTLGW ${name} unexpected info about ${running} received (module crashed?), reopening");
				HMUARTLGW_Reopen($hash);
			}
		} elsif ($msg =~ m/^04(..)/) {
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
		} elsif ($msg =~ m/^05(..)$/) {
			HMUARTLGW_updateMsgLoad($hash, hex($1));
		}
	} elsif ($dst == HMUARTLGW_DST_APP) {

		if ($msg =~ m/^04(..)(.*)$/) {
			my $ack = $1;
			my $oldMsg;

			if ($hash->{DevState} == HMUARTLGW_STATE_SEND) {
				RemoveInternalTimer($hash);
				$hash->{DevState} = HMUARTLGW_STATE_RUNNING;

				$oldMsg = shift @{$hash->{Helper}{PendingCMD}};
			}

			if ($ack eq HMUARTLGW_ACK_WITH_RESPONSE ||
			    $ack eq HMUARTLGW_ACK_WITH_RESPONSE_AES_OK) {
				$recv = "04" . $1 . $2;

			} elsif ($ack eq HMUARTLGW_ACK_WITH_RESPONSE_AES_KO) {
				if ($oldMsg) {
					#Need to produce our own "failed" challenge
					my %addvals = ();
					my $m = substr($oldMsg, 6, 2) .
					        "A0" .
					        substr($oldMsg, 10, 2) .
					        substr($oldMsg, 18, 6) .
					        substr($oldMsg, 12, 6) .
					        "04000000000000" .
					        sprintf("%02X", hex(substr($2, 0, 2))*2);
					my $dmsg = sprintf("A%02X%s:AESpending::${name}", length($m)/2, uc($m));

					Log3($hash, 5, "HMUARTLGW ${name} Dispatch: ${dmsg}");
					Dispatch($hash, $dmsg, \%addvals);

					$dmsg = sprintf("A%02X%s:AESCom-fail::${name}", length($m)/2, uc($m));

					Log3($hash, 5, "HMUARTLGW ${name} Dispatch: ${dmsg}");
					Dispatch($hash, $dmsg, \%addvals);
				}

			} elsif ($ack eq HMUARTLGW_ACK_EINPROGRESS && $oldMsg) {
				Log3($hash, 5, "HMUARTLGW ${name} IO currently busy, trying again in a bit");

				if ($hash->{DevState} == HMUARTLGW_STATE_RUNNING) {
					$hash->{Helper}{RetryCnt}++;
					RemoveInternalTimer($hash);
					unshift @{$hash->{Helper}{PendingCMD}}, $oldMsg;
					InternalTimer(gettimeofday()+0.1, "HMUARTLGW_SendPendingCmd", $hash, 0);
				}
				return;
			} elsif ($ack eq HMUARTLGW_ACK_ENOCREDITS) {
				Log3($hash, 1, "HMUARTLGW ${name} IO in overload!");
				$hash->{XmitOpen} = 0;
			} elsif ($ack eq HMUARTLGW_ACK_ECSMACA && $oldMsg) {
				Log3($hash, 1, "HMUARTLGW ${name} can't send due to CSMA/CA, trying again in a bit");

				if ($hash->{DevState} == HMUARTLGW_STATE_RUNNING) {
					$hash->{Helper}{RetryCnt}++;
					RemoveInternalTimer($hash);
					unshift @{$hash->{Helper}{PendingCMD}}, $oldMsg;
					InternalTimer(gettimeofday()+0.1, "HMUARTLGW_SendPendingCmd", $hash, 0);
				}
				return;
			} elsif ($ack eq HMUARTLGW_ACK_EUNKNOWN && $oldMsg) {
				Log3($hash, 5, "HMUARTLGW ${name} can't send due to unknown problem, trying again in a bit");

				if ($hash->{DevState} == HMUARTLGW_STATE_RUNNING) {
					$hash->{Helper}{RetryCnt}++;
					RemoveInternalTimer($hash);
					unshift @{$hash->{Helper}{PendingCMD}}, $oldMsg;
					InternalTimer(gettimeofday()+0.1, "HMUARTLGW_SendPendingCmd", $hash, 0);
				}
				return;
			} else {
				Log3($hash,1,"HMUARTLGW ${name} Ack: ${ack} ".(($2)?$2:""));
			}

			delete($hash->{Helper}{RetryCnt});
			HMUARTLGW_UpdateQueuedPeer($hash);
			HMUARTLGW_SendPendingCmd($hash);
		} elsif ($msg =~ m/^(05.*)$/) {
			$recv = $1;
		}

		if ($recv && $recv =~ m/^(..)(..)(..)(..)(..)(..)(..)(......)(......)(.*)$/) {
			my ($type, $status, $info, $rssi, $mNr, $flags, $cmd, $src, $dst, $payload) = ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

			Log3($hash, 1, "HMUARTLGW ${name} recv: 01 ${type} ${status} ${info} ${rssi} msg: ${mNr} ${flags} ${cmd} ${src} ${dst} ${payload}");

			return if (!$hash->{Helper}{Initialized});

			$rssi = 0 - hex($rssi);
			$hash->{RSSI} = $rssi;
			my %addvals = (RAWMSG => $msg, RSSI => $rssi);

			my $dmsg;
			my $m = $mNr . $flags . $cmd . $src . $dst . $payload;

			if ($type eq HMUARTLGW_APP_ACK && $status eq HMUARTLGW_ACK_WITH_RESPONSE_AES_OK) {
				#Fake AES challenge for CUL_HM
				my $kNo = sprintf("%02X", (hex($info) * 2));
				my $c = "${mNr}A0${cmd}${src}${dst}04000000000000${kNo}";
				$dmsg = sprintf("A%02X%s:AESpending:${rssi}:${name}", length($c)/2, uc($c));

				$CULinfo = "AESCom-ok";
			} elsif ($type eq HMUARTLGW_APP_RECV && ($status eq HMUARTLGW_RECV_RESP_WITH_AES_OK ||
			                                         $status eq  HMUARTLGW_RECV_TRIG_WITH_AES_OK)) {
				#Fake AES response for CUL_HM
				$dmsg = sprintf("A%02X%s:AESpending:${rssi}:${name}", length($m)/2, uc($m));

				$CULinfo = "AESCom-ok";
			} elsif ($type eq HMUARTLGW_APP_RECV && $status eq HMUARTLGW_RECV_RESP_WITH_AES_KO) {
				#Fake AES response for CUL_HM
				$dmsg = sprintf("A%02X%s:AESpending:${rssi}:${name}", length($m)/2, uc($m));

				$CULinfo = "AESCom-fail";
			}

			if ($dmsg) {
				Log3($hash, 5, "HMUARTLGW ${name} Dispatch: ${dmsg}");
				Dispatch($hash, $dmsg, \%addvals);
			}

			# HMUARTLGW sends ACK for flag 'A0' but not for 'A4'(config mode)-
			# we ack ourself an long as logic is uncertain - also possible is 'A6' for RHS
			if (hex($flags) & 0xA4 == 0xA4 && $hash->{owner} eq $dst) {
				Log3($hash, 1 ,"HMUARTLGW: $name ACK config");
				HMUARTLGW_Write($hash,undef, "As15".$mNr."8002".$dst.$src."00");
			}

			$dmsg = sprintf("A%02X%s:${CULinfo}:${rssi}:${name}", length($m)/2, uc($m));

			Log3($hash, 5, "HMUARTLGW ${name} Dispatch: ${dmsg}");
			Dispatch($hash, $dmsg, \%addvals);
		}
	}

	return;
}

sub HMUARTLGW_Read($)
{
	my ($hash) = @_;
	my $name = $hash->{NAME};

	my $buf = DevIo_SimpleRead($hash);
	return "" if (!defined($buf));

	$buf = HMUARTLGW_decrypt($hash, $buf) if ($hash->{crypto});

	Log3($hash, 5, "HMUARTLGW ${name} read raw (".length($buf)."): ".unpack("H*", $buf));

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

	while (defined($p) && $p =~ m/^\xfd/) {
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
			if ($unescape_next) {
				$byte = chr(ord($byte)|0x80);
				$unescape_next = 0;
			}
			$unescaped .= $byte;
		}

		next if (length($unescaped) < 7); #len len dst cnt cmd crc crc

		(my $len) = unpack("n", substr($unescaped, 0, 2));

		if (length($unescaped) > $len + 4) {
			Log3($hash, 1, "HMUARTLGW ${name} frame with wrong length received: ".length($unescaped).", should: ".($len + 4).": FD".uc(unpack("H*", $unescaped)));
			next;
		}

		next if (length($unescaped) < $len + 4); #short read

		my $crc = HMUARTLGW_crc16(chr(0xfd).$unescaped);
		if ($crc != 0x0000) {
			Log3($hash, 1, "HMUARTLGW ${name} invalid checksum received, dropping frame (FD".uc(unpack("H*", $unescaped)).")!");
			undef($unprocessed);
			next;
		}

		Log3($hash, 5, "HMUARTLGW ${name} read (".length($unescaped)."): fd".unpack("H*", $unescaped)." crc OK");

		my $dst = ord(substr($unescaped, 2, 1));
		$hash->{DEVCNT} = ord(substr($unescaped, 3, 1));

		HMUARTLGW_Parse($hash, uc(unpack("H*", substr($unescaped, 4, -2))), $dst);

		undef($unprocessed);
	}

	if (defined($unprocessed)) {
		$hash->{PARTIAL} = unpack("H*", $unprocessed);
	} else {
		$hash->{PARTIAL} = '';
	}
}

sub HMUARTLGW_Write($$$)
{
	my ($hash,$fn,$msg) = @_;
	my $name = $hash->{NAME};

	if($msg =~ m/init:(......)/) {
		my $dst = $1;
		if ($modules{CUL_HM}{defptr}{$dst} &&
		    $modules{CUL_HM}{defptr}{$dst}{helper}{io}{newChn}) {
			my ($id, $flags, $kNo, $aesChannels) = split(/,/, $modules{CUL_HM}{defptr}{$dst}{helper}{io}{newChn});
			my $peer = {
				id => substr($id, 1),
				operation => substr($id, 0, 1),
				flags => $flags,
				kNo => $kNo,
				aesChannels => $aesChannels,
			};
			$hash->{Peers}{$peer->{id}} = "pending";
			HMUARTLGW_UpdatePeer($hash, $peer);
		}
		return;
	} elsif ($msg =~ m/remove:(......)/) {
		my $peer = {
			id => $1,
			operation => "-",
		};
		delete($hash->{Peers}{$peer->{id}});
		HMUARTLGW_UpdatePeer($hash, $peer);
	} elsif ($msg =~ m/^([+-])(.*)$/) {
		my ($id, $flags, $kNo, $aesChannels) = split(/,/, $msg);
		my $peer = {
			id => substr($id, 1),
			operation => substr($id, 0, 1),
			flags => $flags,
			kNo => $kNo,
			aesChannels => $aesChannels,
		};
		if ($peer->{operation} eq "+") {
			$hash->{Peers}{$peer->{id}} = "pending";
		} else {
			delete($hash->{Peers}{$peer->{id}});
		}
		HMUARTLGW_UpdatePeer($hash, $peer);
		return;
	} elsif ($msg =~ m/^writeAesKey:(.*)$/) {
		HMUARTLGW_writeAesKey($1);
		return;
	} elsif (length($msg) > 21) {
		my ($mtype,$src,$dst) = (substr($msg, 8, 2),
		                         substr($msg, 10, 6),
		                         substr($msg, 16, 6));

		if ($mtype eq "02" && $src eq $hash->{owner} && length($msg) == 24 &&
		    defined($hash->{Peers}{$dst})){
			# Acks are generally send by HMUARTLGW autonomously
			# Special
			Log3($hash, 5, "HMUARTLGW: Skip ACK");
			return;
		}

		if (!$hash->{Peers}{$dst} && $dst ne "000000"){
			#add id and enqueue command
			my $peer = {
				id => $dst,
				operation => "+",
				flags => "00",
				kNo => "00",
			};
			HMUARTLGW_UpdatePeer($hash, $peer);
		}

		my $cmd = HMUARTLGW_APP_SEND . "0000";

		if ($hash->{FW} > 0x010006) { #TODO: Find real version which adds this
			$cmd .= ((hex(substr($msg, 6, 2)) & 0x10) ? "01" : "00");
		}

		$cmd .= substr($msg, 4);

		push @{$hash->{Helper}{PendingCMD}}, $cmd;
		push @{$hash->{Helper}{PendingCMD}}, "Credits" if ((++$hash->{Helper}{SendCnt} % 10) == 0);
		HMUARTLGW_SendPendingCmd($hash);
	} else {
		Log3($hash,1,"HMUARTLGW ${name} write:${fn} ${msg}");
	}


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

	Log3($hash, 4, "HMUARTLGW ${name} StartInit");

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
		Log3($hash, 1, "HMUARTLGW ${name} did not respond, reopening");
		HMUARTLGW_Reopen($hash);
	}

	return;
}

sub HMUARTLGW_Get($@)
{
}

sub HMUARTLGW_RemoveHMPair($)
{
	my ($in) = shift;
	my (undef,$name) = split(':',$in);
	my $hash = $defs{$name};
	RemoveInternalTimer("hmPairForSec:$name");
	Log3($hash, 3, "HMUARTLGW ${name} left pairing-mode") if ($hash->{hmPair});
	delete($hash->{hmPair});
	delete($hash->{hmPairSerial});
}

sub HMUARTLGW_Set($@)
{
	my ($hash, $name, $cmd, @a) = @_;

	my $arg = join(" ", @a);

	return "\"set\" needs at least one parameter" if (!$cmd);
	return "Unknown argument ${cmd}, choose one of " . join(" ", sort keys %sets)
	    if(!defined($sets{$cmd}));

	if ($cmd eq "hmPairForSec") {
		$arg = 60 if(!$arg || $arg !~ m/^\d+$/);
		HMUARTLGW_RemoveHMPair("hmPairForSec:$name");
		$hash->{hmPair} = 1;
		InternalTimer(gettimeofday()+$arg, "HMUARTLGW_RemoveHMPair", "hmPairForSec:$name", 1);
		Log3($hash, 3, "HMUARTLGW ${name} entered pairing-mode");
	} elsif ($cmd eq "hmPairSerial") {
		return "Usage: set $name hmPairSerial <10-character-serialnumber>"
		    if(!$arg || $arg !~ m/^.{10}$/);

		my $id = InternalVal($hash->{NAME}, "owner", "123456");
		$hash->{HM_CMDNR} = $hash->{HM_CMDNR} ? ($hash->{HM_CMDNR}+1)%256 : 1;

		HMUARTLGW_Write($hash, undef, sprintf("As15%02X8401%s000000010A%s",
					$hash->{HM_CMDNR}, $id, unpack('H*', $arg)));
		HMUARTLGW_RemoveHMPair("hmPairForSec:$name");
		$hash->{hmPair} = 1;
		$hash->{hmPairSerial} = $arg;
		InternalTimer(gettimeofday()+20, "HMUARTLGW_RemoveHMPair", "hmPairForSec:".$name, 1);
	} elsif ($cmd eq "reopen") {
		HMUARTLGW_Reopen($hash);
	}

	return undef;
}

sub HMUARTLGW_Attr(@)
{
	my ($cmd, $name, $aName, $aVal) = @_;
	my $hash = $defs{$name};

	my $retVal;

	Log3($hash,5,"HMUARTLGW ${name} Attr ${cmd} ${aName} ${aVal}");

	return if (!$init_done);

	if ($aName eq "hmId") {
		if ($cmd eq "set") {
			my $owner_ccu = InternalVal($name, "owner_CCU", undef);
			return "device owned by $owner_ccu" if ($owner_ccu);
			return "wrong syntax: hmId must be 6-digit-hex-code (3 byte)"
			    if ($aVal !~ m/^[A-F0-9]{6}$/i);

			$hash->{Helper}{OneParameterOnly} = 1;
			$hash->{DevState} = HMUARTLGW_STATE_SET_HMID;
			HMUARTLGW_GetSetParameterReq($hash, $aVal);
		}
	} elsif ($aName eq "lgwPw") {
		if ($hash->{DevType} eq "LGW") {
			HMUARTLGW_Reopen($hash);
		}
	} elsif ($aName =~ m/^hmKey(.?)$/) {
		if ($cmd eq "set") {
			my $kNo = 1;
			$kNo = $1 if ($1);
			my ($no,$val) = (sprintf("%02X",$kNo),$aVal);
			if ($aVal =~ m/:/){#number given
				($no,$val) = split ":",$aVal;
				return "illegal number:$no" if (hex($no) < 1 || hex($no) > 255 || length($no) != 2);
			}
			$attr{$name}{$aName} = "$no:".
				(($val =~ m /^[0-9A-Fa-f]{32}$/ )
				 ? $val
				 : unpack('H*', md5($val)));
			$retVal = "$aName set to $attr{$name}{$aName}"
				if($aVal ne $attr{$name}{$aName});
		} else {
			delete $attr{$name}{$aName};
		}
		HMUARTLGW_writeAesKey($name);
	} elsif ($aName eq "dutyCycle") {
		my $dutyCycle = 1;
		if ($cmd eq "set") {
			return "wrong syntax: dutyCycle must be 1 or 0"
			    if ($aVal !~ m/^[01]$/);
			$dutyCycle = $aVal;
		}

		$hash->{Helper}{OneParameterOnly} = 1;
		$hash->{DevState} = HMUARTLGW_STATE_ENABLE_CREDITS;
		HMUARTLGW_GetSetParameterReq($hash, $dutyCycle);
	} elsif ($aName eq "CSMA/CA") {
		my $csma_ca = 1;
		if ($cmd eq "set") {
			return "wrong syntax: CSMA/CA must be 1 or 0"
			    if ($aVal !~ m/^[01]$/);
			$csma_ca = $aVal;
		}

		$hash->{Helper}{OneParameterOnly} = 1;
		$hash->{DevState} = HMUARTLGW_STATE_ENABLE_CSMACA;
		HMUARTLGW_GetSetParameterReq($hash, $csma_ca);
	}

	return $retVal;
}

sub HMUARTLGW_getAesKeys($) {
	my ($hash) = @_;
	my $name = $hash->{NAME};
	my @k;

	my %keys = ();
	my $vccu = InternalVal($name,"owner_CCU",$name);
	$vccu = $name if(!AttrVal($vccu,"hmKey",""));
	foreach my $i (1..3){
		my ($kNo,$k) = split(":",AttrVal($vccu,"hmKey".($i== 1?"":$i),""));
		if (defined($kNo) && defined($k)) {
			$keys{$kNo} = $k;
		}
	}

	my @kNos = reverse(sort(keys(%keys)));
	foreach my $kNo (@kNos) {
		Log3($hash,1,"HMUARTLGW ${name} key: ".$keys{$kNo}.", idx: ".$kNo);
		push @k, $keys{$kNo} . $kNo;
	}

	return @k;
}

sub HMUARTLGW_writeAesKey($) {
	my ($name) = @_;
	return if (!$name || !$defs{$name} || $defs{$name}{TYPE} ne "HMUARTLGW");
	my $hash = $defs{$name};

	push @{$hash->{Helper}{PendingCMD}}, "AESkeys";
	HMUARTLGW_SendPendingCmd($hash);
}

sub HMUARTLGW_updateMsgLoad($$) {
	my ($hash, $load) = @_;

	if ($load >= 199) {
		$hash->{XmitOpen} = 0;
	} else {
		$hash->{XmitOpen} = 1;
	}
	$hash->{msgLoadCurrent} = $load;
}

sub HMUARTLGW_send($$$)
{
	my ($hash, $msg, $dst) = @_;
	my $name = $hash->{NAME};

	my $log;

	if ($dst == HMUARTLGW_DST_APP && uc($msg) =~ m/^(02)(..)(..)(.*)$/) {
		$log = "01 ${1} ${2} ${3} ";

		my $m = $4;

		if ($hash->{FW} > 0x010006) {
			$log .= substr($m, 0, 2, '') . " ";
		} else {
			$log .= "XX ";
		}

		if ($m =~ m/^(..)(..)(..)(......)(......)(.*)$/) {
			$log .= "msg: ${1} ${2} ${3} ${4} ${5} ${6}";
		} else {
			$log .= $m;
		}
	} else {
		$log = sprintf("%02X", $dst). " ".uc($msg);
	}

	Log3($hash, 1, "HMUARTLGW ${name} send: ${log}");

	$hash->{CNT} = ($hash->{CNT} + 1) & 0xff;

	my $frame = pack("CnCCH*", 0xfd,
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

	Log3($hash,5,"HMUARTLGW ${name} send (".length($frame)."): ".unpack("H*", $frame));

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

	Log3($hash, 4, "HMUARTLGW ${name} send (".length($msg)."): ". $msg =~ s/\r\n//r);
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

	while(length($plaintext)) {
		if(length($ks)) {
			my $len = length($plaintext);

			$len = length($ks) if (length($ks) < $len);

			my $ppart = substr($plaintext, 0, $len, '');
			my $kpart = substr($ks, 0, $len, '');

			$ct .= $ppart ^ $kpart;

			$ciphertext .= $ppart ^ $kpart;
		} else {
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

	while(length($ciphertext)) {
		if(length($ks)) {
			my $len = length($ciphertext);

			$len = length($ks) if (length($ks) < $len);

			my $cpart = substr($ciphertext, 0, $len, '');
			my $kpart = substr($ks, 0, $len, '');

			$ct .= $cpart;

			$plaintext .= $cpart ^ $kpart;
		} else {
			$ks = $hash->{crypto}{cipher}->encrypt($ct);
			$ct='';
		}
	}

	$hash->{crypto}{decrypt}{keystream} = unpack("H*", $ks);
	$hash->{crypto}{decrypt}{ciphertext} = unpack("H*", $ct);

	$plaintext;
}

1;

=pod
=begin html

<a name="HMUARTLGW"></a>
<h3>HMUARTLGW</h3>
<ul>
  HMUARTLGW is the Fhem module for the eQ-3 HomeMatic Wireless LAN Gateway
  (HM-LGW-O-TW-W-EU) and the eQ-3 HomeMatic UART module (HM-MOD-UART), which
  is part of the HomeMatic wireless module for the Raspberry Pi
  (HM-MOD-RPI-PCB).<br>

  <br><br>

  <a name="HMUARTLGHW_define"></a>
  <b>Define</b>
  <ul>
    <code>define &lt;name&gt; HMUARTLGW &lt;device&gt;</code><br><br>
    The &lt;device&gt;-parameter depends on the device-type:
    <ul>
      <li>HM-MOD-UART: &lt;device&gt; specifies the serial port to communicate
          with. The baud-rate is fixed at 115200 and does not need to be
          specified.</li>
      <li>HM-LGW-O-TW-W-EU: &lt;device&gt; specifies the IP address or hostname
          of the gateway, optionally followed by : and the port number of the
          BidCoS-port (default when not specified: 2000).</li>
    </ul>
    <br><br>
    Examples:<br>
    <ul>
      <code>define myHmUART HMUARTLGW /dev/ttyAMA0</code><br>
      <code>define myHmLGW HMUARTLGW 192.168.42.23</code><br>
    </ul>
  </ul>
  <br>
  <a name="HMUARTLGW_set"></a>
  <p><b>Set</b></p>
  <ul>
    <li><a href="#hmPairForSec">hmPairForSec</a></li>
    <li><a href="#hmPairSerial">hmPairSerial</a></li>
    <li>reopen<br>
        Reopens the connection to the device and reinitializes it.
        </li><br>
  </ul>
  <br>
  <a name="HMUARTLGW_get"></a>
  <b>Get</b> <ul>N/A</ul><br>
  <a name="HMUARTLGW_attr"></a>
  <b>Attributes</b>
  <ul>
    <li><a href="#hmId">hmId</a></li>
    <li><a name="HMLANhmKey">hmKey</a></li>
    <li><a name="HMLANhmKey2">hmKey2</a></li>
    <li><a name="HMLANhmKey3">hmKey3</a></li>
    <li>lgwPw<br>
        AES password for the eQ-3 HomeMatic Wireless LAN Gateway. The default
        password is printed on the back of the device (but can be changed by
        the user). If AES communication is enabled on the LAN Gateway (default),
        this attribute has to be set to the correct value or communication will
        not be possible. In addition, the perl-module Crypt::Rijndael (which
        provides the AES cipher) must be installed.
        </li><br>
    <li>dutyCycle<br>
        Enable or disable the duty-cycle check (1% rule) performed by the
	wireless module.<br>
        Disabling this might be illegal in your country, please check with local
        regulations!<br>
        Default: 1 (enabled)
        </li><br>
    <li>CSMA/CA<br>
        Enable or disable CSMA/CA (Carrier sense multiple access with collision
        avoidance), also known as listen-before-talk.
        Disabling this might be illegal in your country, please check with local
        regulations!<br>
        Default: 1 (enabled)
        </li><br>
  </ul>
  <br>

</ul>

=end html
=cut
