#!/usr/bin/perl
#
# mbsync - mailbox synchronizer
# Copyright (C) 2017 Oswald Buddenhagen <ossi@users.sf.net>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# As a special exception, mbsync may be linked with the OpenSSL library,
# despite that library's more restrictive license.
#

use strict;
use warnings;

die("Usage: $0 driver.h drv_proxy.c drv_proxy.inc\n")
	if ($#ARGV != 2);

my ($in_header, $in_source, $out_source) = @ARGV;

my %templates;
my %defines;
my %excluded;
my %special;

open(my $ins, $in_source) or die("Cannot open $in_source: $!\n");
my $template;
my $define;
my $conts;
while (<$ins>) {
	if ($template) {
		if (/^\/\/\# END$/) {
			$templates{$template} = $conts;
			$template = undef;
		} else {
			$conts .= $_;
		}
	} elsif ($define) {
		if (/^\/\/\# END$/) {
			$defines{$define} = $conts;
			$define = undef;
		} else {
			$conts .= $_;
		}
	} else {
		if (/^\/\/\# TEMPLATE (\w+)$/) {
			$template = $1;
			$conts = "";
		} elsif (/^\/\/\# DEFINE (\w+)$/) {
			$define = $1;
			$conts = "";
		} elsif (/^\/\/\# DEFINE (\w+) (.*)$/) {
			$defines{$1} = $2;
		} elsif (/^\/\/\# UNDEFINE (\w+)$/) {
			$defines{$1} = "";
		} elsif (/^\/\/\# EXCLUDE (\w+)$/) {
			$excluded{$1} = 1;
		} elsif (/^\/\/\# SPECIAL (\w+)$/) {
			$special{$1} = 1;
		}
	}
}
close($ins);

open(my $inh, $in_header) or die("Cannot open $in_header: $!\n");
my $sts = 0;
my $cont = "";
while (<$inh>) {
	if ($sts == 0) {
		if (/^struct driver \{$/) {
			$sts = 1;
		}
	} elsif ($sts == 1) {
		if (/^\};$/) {
			$sts = 0;
		} else {
			$cont .= $_;
		}
	}
}
close($inh);

$cont =~ s,\n, ,g;
$cont =~ s,/\*.*?\*/, ,g;
$cont =~ s,\h+, ,g;
my @ptypes = map { s,^ ,,r } split(/;/, $cont);
pop @ptypes;  # last one is empty

my @cmd_table;

sub make_args($)
{
	$_ = shift;
	s/(?:^|(?<=, ))(?:const )?\w+ \*?//g;
	return $_;
}

sub type_to_format($)
{
	$_ = shift;
	s/xint /\%\#x/g;
	s/int /\%d/g;
	s/const char \*/\%s/g;
	return $_;
}

sub make_format($)
{
	$_ = type_to_format(shift);
	s/, (\%\#?.)(\w+)/, $2=$1/g;
	return $_;
}

open(my $outh, ">".$out_source) or die("Cannot create $out_source: $!\n");

for (@ptypes) {
	/^([\w* ]+)\(\*(\w+)\)\( (.*) \)$/ or die("Cannot parse prototype '$_'\n");
	my ($cmd_type, $cmd_name, $cmd_args) = ($1, $2, $3);
	if (defined($excluded{$cmd_name})) {
		push @cmd_table, "0";
		next;
	}
	push @cmd_table, "proxy_$cmd_name";
	next if (defined($special{$cmd_name}));
	my %replace;
	$replace{'name'} = $cmd_name;
	$replace{'type'} = $cmd_type;
	$cmd_args =~ s/^store_t \*ctx// or die("Arguments '$cmd_args' don't start with 'store_t *ctx'\n");
	if ($cmd_type eq "void " && $cmd_args =~ s/, void \(\*cb\)\( (.*)void \*aux \), void \*aux$//) {
		my $cmd_cb_args = $1;
		$replace{'decl_cb_args'} = $cmd_cb_args;
		$replace{'pass_cb_args'} = make_args($cmd_cb_args);
		my $cmd_print_cb_args = $cmd_cb_args =~ s/(.*), $/, $1/r;
		$replace{'print_pass_cb_args'} = make_args($cmd_print_cb_args);
		$replace{'print_fmt_cb_args'} = make_format($cmd_print_cb_args);
		$template = "CALLBACK";
	} elsif ($cmd_name =~ /^get_/) {
		$template = "GETTER";
		$replace{'fmt'} = type_to_format($cmd_type);
	} elsif ($cmd_type eq "void ") {
		$template = "REGULAR_VOID";
	} else {
		$template = "REGULAR";
		$replace{'fmt'} = type_to_format($cmd_type);
	}
	$replace{'decl_args'} = $cmd_args;
	$replace{'print_pass_args'} = $replace{'pass_args'} = make_args($cmd_args);
	$replace{'print_fmt_args'} = make_format($cmd_args);
	for (keys %defines) {
		$replace{$1} = $defines{$_} if (/^${cmd_name}_(.*)$/);
	}
	my $text = $templates{$template};
	$text =~ s/^\h*\@(\w+)\@\n/$replace{$1} \/\/ ""/smeg;
	$text =~ s/\@(\w+)\@/$replace{$1} \/\/ ""/eg;
	print $outh $text."\n";
}

print $outh "struct driver proxy_driver = {\n".join("", map { "\t$_,\n" } @cmd_table)."};\n";
close $outh;
