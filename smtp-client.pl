#!/usr/bin/perl

# 
# Simple SMTP client with STARTTLS and AUTH support.
# Michal Ludvig <michal@logix.cz>, 2003-2008
# See http://www.logix.cz/michal/devel/smtp for details.
# Thanks to all contributors for ideas and fixes!
# 

# 
# This program is licensed under GNU Public License v2 (GPLv2)
# 

## Require Perl 5.8 or higher -> we need open(.., .., \$variable) construct
require 5.008;

use strict;
use IO::Socket::INET;
use IO::Socket::SSL;
use Net::SSLeay;
use Digest::HMAC_MD5 qw(hmac_md5_hex);
use MIME::Base64 qw(encode_base64 decode_base64);
use Getopt::Long;
use Socket qw(:DEFAULT :crlf);

my ($user, $pass, $host, $port, 
    $use_login, $use_plain, $use_cram_md5, $use_digest_md5, 
    $ehlo_ok, $auth_ok, $starttls_ok, $verbose, 
    $hello_host, $from, @to, $datasrc,
    $missing_modules_ok, $missing_modules_count,
    $subject, $body_plain, $body_html, @attachments, @attachments_inline, $built_message);

$host = 'localhost';
$port = 'smtp(25)';
$hello_host = 'localhost';
$verbose = 0;
$use_login = 0;
$use_plain = 0;
$use_cram_md5 = 0;
$use_digest_md5 = 0;
$starttls_ok = 1;
$auth_ok = 0;
$ehlo_ok = 1;
$missing_modules_ok = 0;
$missing_modules_count = 0;

# Get command line options.
GetOptions (
	'host|server=s' => \$host,
	'port=i' => \$port, 
	'user=s' => \$user, 'password=s' => \$pass,
	'auth-login' => \$use_login, 
	'auth-plain' => \$use_plain,
	'auth-cram-md5' => \$use_cram_md5, 
	'auth-digest-md5' => \$use_digest_md5,
	'disable-ehlo' => sub { $ehlo_ok = 0; },
	'force-ehlo' => sub { $ehlo_ok = 2; },
	'hello-host|ehlo-host|helo-host=s' => \$hello_host,
	'enable-auth' => \$auth_ok,
	'disable-starttls|disable-tls|disable-ssl' => 
		sub { $starttls_ok = 0; },
	'from|mail-from=s' => \$from,
	'to|rcpt-to=s' => \@to,
	'data=s' => \$datasrc,
	'subject=s' => \$subject,
	'body|body-plain=s' => \$body_plain,
	'body-html=s' => \$body_html,
	'attachment|attach=s' => \@attachments,
	'attachment-inline|attach-inline=s' => \@attachments_inline,
	'missing-modules-ok' => \$missing_modules_ok,
	'verbose:1' => \$verbose,
	'help' => sub { &usage() } );

#### Try to load optional modules

## MIME::Lite dependency is optional
my $mime_lite = eval { require MIME::Lite; 1; };
if (not $mime_lite and not $missing_modules_ok) {
	warn("!!! MIME::Lite -- optional module not found\n");
	warn("!!! Used for composing messages from --subject, --body, --attachment, etc.\n\n");
	$missing_modules_count++;
}

## File::Type dependency is optional
my $file_type = eval { require File::Type; File::Type->new(); };
if (not $file_type and not $missing_modules_ok) {
	warn("!!! File::Type -- optional module not found\n");
	warn("!!! used for guessing MIME types of attachments\n\n");
	$missing_modules_count++;
}

## Term::ReadKey dependency is optional
my $term_readkey = eval { require Term::ReadKey; 1; };
if (not $term_readkey and not $missing_modules_ok) {
	warn("!!! Term::ReadKey -- optional module not found\n");
	warn("!!! used for hidden reading SMTP password from the terminal\n\n");
	$missing_modules_count++;
}

## Advise about --missing-modules-ok parameter
if ($missing_modules_count) {
	warn("!!! Use --missing-modules-ok if you don't need the above listed modules\n");
	warn("!!! and don't want to see this message again.\n\n");
}

## Accept hostname with port number as host:port
if ($host =~ /^(.*):(.*)$/)
{
	$host = $1;
	$port = $2;
}

# Build the MIME message if required
if (defined($subject) or defined($body_plain) or defined($body_html) or
    	defined(@attachments) or defined(@attachments_inline)) {
	if (not $mime_lite) {
		die("Module MIME::Lite is not available. Unable to build the message, sorry.\n".
		    "Use --data and provide a complete email payload including headers instead.\n");
	}
	if (defined($datasrc)) {
		die("Requested building a message and at the same time used --data parameter.\n".
		    "That's not possible, sorry.\n");
	}
	if (defined($body_plain) and -f $body_plain) {
		local $/=undef;
		open(FILE, $body_plain);
		$body_plain = <FILE>;
		close(FILE);
	}
	if (defined($body_html) and -f $body_html) {
		local $/=undef;
		open(FILE, $body_html);
		$body_html = <FILE>;
		close(FILE);
	}
	my $message = &build_message();

	open(BUILT_MESSAGE, "+>", \$built_message);
	$datasrc = "///built_message";
	$message->print(\*BUILT_MESSAGE);
	seek(BUILT_MESSAGE, 0, 0);

}
# If at least one --auth-* option was given, enable AUTH.
if ($use_login + $use_plain + $use_cram_md5 + $use_digest_md5 > 0)
	{ $auth_ok = 1; }

# If --enable-auth was given, enable all AUTH methods.
elsif ($auth_ok && ($use_login + $use_plain + $use_cram_md5 
                    + $use_digest_md5 == 0))
{
	$use_login = 1;
	$use_plain = 1;
	$use_cram_md5 = 1;
	$use_digest_md5 = 1;
}

# Exit if user haven't specified username for AUTH.
if ($auth_ok && !defined ($user))
	{ die ("You requested SMTP AUTH support. Consider using --user switch as well.\n"); }

# Ask for password if it wasn't supplied on the command line.
if ($auth_ok && defined ($user) && !defined ($pass))
{
	printf ("Enter password for %s@%s : ", $user, $host);
	# Set echo off.
	ReadMode (2);
	$pass = <>;
	# Restore echo.
	ReadMode (0);
	printf ("\n");

	exit if (! defined ($pass));
	chop ($pass);
}

# Connect to the SMTP server.
my $sock = IO::Socket::INET->new(
	PeerAddr => $host,
	PeerPort => $port,
	Proto => 'tcp',
	Timeout => 5)
	or die ("Connect failed: $@\n");

my ($code, $text);
my (%features);

# Wait for the welcome message of the server.
($code, $text) = &get_line ($sock);
die ("Unknown welcome string: '$code $text'\n") if ($code != 220);
$ehlo_ok-- if ($text !~ /ESMTP/);

# Send EHLO
&say_hello ($sock, $ehlo_ok, $hello_host, \%features) or exit (1);

# Run the SMTP session
&run_smtp ();

# Good bye...
&send_line ($sock, "QUIT\n");
($code, $text) = &get_line ($sock);
die ("Unknown QUIT response '$code'.\n") if ($code != 221);

exit 0;

# This is the main SMTP "engine".
sub run_smtp
{
	# See if we could start encryption
	if ((defined ($features{'STARTTLS'}) || defined ($features{'TLS'})) && $starttls_ok)
	{
		printf ("Starting TLS...\n") if ($verbose >= 1);

		# Do Net::SSLeay initialization
		Net::SSLeay::load_error_strings();
		Net::SSLeay::SSLeay_add_ssl_algorithms();
		Net::SSLeay::randomize();
	
		&send_line ($sock, "STARTTLS\n");
		($code, $text) = &get_line ($sock);
		die ("Unknown STARTTLS response '$code'.\n") if ($code != 220);
		
		if (! IO::Socket::SSL::socket_to_SSL($sock, 
			SSL_version => 'SSLv3 TLSv1'))
		{
			die ("STARTTLS: ".IO::Socket::SSL::errstr()."\n"); 
		}
		
		if ($verbose >= 1)
		{
			printf ("Using cipher: %s\n", $sock->get_cipher ());
			printf ("%s", $sock->dump_peer_certificate());
		}

		# Send EHLO again (required by the SMTP standard).
		&say_hello ($sock, $ehlo_ok, $hello_host, \%features) or return 0;
	}
	
	# See if we should authenticate ourself
	if (defined ($features{'AUTH'}) && $auth_ok)
	{
		if ($verbose >= 1)
		{
			printf ("AUTH method (%s): ", $features{'AUTH'});
		}

		# Try CRAM-MD5 if supported by the server
		if ($features{'AUTH'} =~ /CRAM-MD5/i && $use_cram_md5)
		{
			printf ("using CRAM-MD5\n") if ($verbose >= 1);
			&send_line ($sock, "AUTH CRAM-MD5\n");
			($code, $text) = &get_line ($sock);
			if ($code != 334)
			{
				warn ("AUTH failed '$code $text'.\n");
				return 0;
			}
	
			my $response = &encode_cram_md5 ($text, $user, $pass);
			&send_line ($sock, "%s\n", $response);
			($code, $text) = &get_line ($sock);
			if ($code != 235)
			{
				warn ("AUTH failed: '$code'.\n");
				return 0;
			}
		}
		# Or try LOGIN method
		elsif ($features{'AUTH'} =~ /LOGIN/i && $use_login)
		{
			printf ("using LOGIN\n") if ($verbose >= 1);
			&send_line ($sock, "AUTH LOGIN\n");
			($code, $text) = &get_line ($sock);
			if ($code != 334)
			{
				warn ("AUTH failed '$code $text'.\n");
				return 0;
			}
			
			&send_line ($sock, "%s\n", encode_base64 ($user, ""));

			($code, $text) = &get_line ($sock);
			if ($code != 334)
			{
				warn ("AUTH failed '$code $text'.\n");
				return 0;
			}
			
			&send_line ($sock, "%s\n", encode_base64 ($pass, ""));

			($code, $text) = &get_line ($sock);
			if ($code != 235)
			{
				warn ("AUTH failed '$code $text'.\n");
				return 0;
			}
		}
		# Or finally PLAIN if nothing else was supported.
		elsif ($features{'AUTH'} =~ /PLAIN/i && $use_plain)
		{
			printf ("using PLAIN\n") if ($verbose >= 1);
			&send_line ($sock, "AUTH PLAIN %s\n", 
				encode_base64 ("$user\0$user\0$pass", ""));
			($code, $text) = &get_line ($sock);
			if ($code != 235)
			{
				warn ("AUTH failed '$code $text'.\n");
				return 0;
			}
		}
		# Complain otherwise.
		else
		{
			warn ("No supported authentication method\n".
			      "advertised by the server.\n");
			return 0;
		}
		
		if ($verbose >= 1)
		{ printf ("Authentication of $user\@$host succeeded\n"); }
	}
	
	# We can do a relay-test now if a recipient was set.
	if ($#to >= 0)
	{
		if (!defined ($from))
		{
			warn ("From: address not set. Using empty one.\n");
			$from = "";
		}
		&send_line ($sock, "MAIL FROM: <%s>\n", $from);
		($code, $text) = &get_line ($sock);
		if ($code != 250)
		{
			warn ("MAIL FROM failed: '$code $text'\n");
			return 0;
		}

		my $i;
		for ($i=0; $i <= $#to; $i++)
		{
			&send_line ($sock, "RCPT TO: <%s>\n", $to[$i]);
			($code, $text) = &get_line ($sock);
			if ($code != 250)
			{
				warn ("RCPT TO <".$to[$i]."> ".
				      "failed: '$code $text'\n");
				return 0;
			}
		}
	}

	# Wow, we should even send something!
	if (defined ($datasrc))
	{
		if ($datasrc eq "///built_message")
		{
			*MAIL = *BUILT_MESSAGE;
		}
		elsif ($datasrc eq "-")
		{
			*MAIL = *STDIN;
		}
		elsif (!open (MAIL, $datasrc))
		{
			warn ("Can't open file '$datasrc'\n");
			return 0;
		}

		&send_line ($sock, "DATA\n");
		($code, $text) = &get_line ($sock);
		if ($code != 354)
		{
			warn ("DATA failed: '$code $text'\n");
			return 0;
		}

		while (<MAIL>)
		{
			my $line = $_;
			$line =~ s/^\.$CRLF$/\. $CRLF/;
			$line =~ s/^\.\n$/\. $CRLF/;
			$sock->print ($line);
		}

		close (MAIL);

		$sock->printf ("$CRLF.$CRLF");

		($code, $text) = &get_line ($sock);
		if ($code != 250)
		{
			warn ("DATA not send: '$code $text'\n");
			return 0;
		}
	}

	# Perfect. Everything succeeded!
	return 1;
}

# Get one line of response from the server.
sub get_one_line ($)
{
	my $sock = shift;
	my ($code, $sep, $text) = ($sock->getline() =~ /(\d+)(.)([^\r]*)/);
	my $more;
	$more = ($sep eq "-");
	if ($verbose)
		{ printf ("[%d] '%s'\n", $code, $text); }
	return ($code, $text, $more);
}

# Get concatenated lines of response from the server.
sub get_line ($)
{
	my $sock = shift;
	my ($code, $text, $more) = &get_one_line ($sock);
	while ($more) {
		my ($code2, $line);
		($code2, $line, $more) = &get_one_line ($sock);
		$text .= " $line";
		die ("Error code changed from $code to $code2. That's illegal.\n") if ($code ne $code2);
	}
	return ($code, $text);
}

# Send one line back to the server
sub send_line ($@)
{
	my $socket = shift;
	my @args = @_;

	if ($verbose)
		{ printf ("> "); printf (@args); }
	$args[0] =~ s/\n/$CRLF/g;
	$socket->printf (@args);
}

# Helper function to encode CRAM-MD5 challenge
sub encode_cram_md5 ($$$)
{
	my ($ticket64, $username, $password) = @_;
	my $ticket = decode_base64($ticket64) or
		die ("Unable to decode Base64 encoded string '$ticket64'\n");
	
	my $password_md5 = hmac_md5_hex($ticket, $password);
	return encode_base64 ("$username $password_md5", "");
}

# Store all server's ESMTP features to a hash.
sub say_hello ($$$$)
{
	my ($sock, $ehlo_ok, $hello_host, $featref) = @_;
	my ($feat, $param);
	my $hello_cmd = $ehlo_ok > 0 ? "EHLO" : "HELO";
	
	&send_line ($sock, "$hello_cmd $hello_host\n");
	my ($code, $text, $more) = &get_one_line ($sock);

	if ($code != 250)
	{
		warn ("$hello_cmd failed: '$code $text'\n");
		return 0;
	}
	
	# Empty the hash
	%{$featref} = ();
	
	($feat, $param) = ($text =~ /^(\w+)[= ]*(.*)$/);
	$featref->{$feat} = $param;

	# Load all features presented by the server into the hash
	while ($more == 1)
	{
		($code, $text, $more) = &get_one_line ($sock);
		($feat, $param) = ($text =~ /^(\w+)[= ]*(.*)$/);
		$featref->{$feat} = $param;
	}

	return 1;
}

sub guess_mime_type($)
{
	my $filename = shift;
	if (defined($file_type)) {
		## Use File::Type if possible
		return $file_type->mime_type($filename);
	} else {
		## Module File::Type is not available
		## Still recognise some common extensions
		return "image/jpeg" if ($filename =~ /\.jpe?g/i);
		return "image/gif" if ($filename =~ /\.gif/i);
		return "image/png" if ($filename =~ /\.png/i);
		return "text/plain" if ($filename =~ /\.txt/i);
		return "application/zip" if ($filename =~ /\.zip/i);
		return "application/x-gzip" if ($filename =~ /\.t?gz/i);
		return "application/x-bzip" if ($filename =~ /\.t?bz2?/i);
	}
	return "application/octet-stream";
}

sub basename($)
{
	my $path = shift;
	my @parts = split(/\//, $path);
	return $parts[$#parts];
}

sub prepare_attachment($)
{
	my $attachment = shift;
	my ($path, $mime_type);

	if (-f $attachment) {
		$path = $attachment;
		$mime_type = guess_mime_type($attachment);
	} elsif ($attachment =~ /(.*)@([^@]*)$/ and -f $1) {
		$path = $1;
		$mime_type = $2;
	}
	return ($path, $mime_type);
}

sub attach_attachments($@) 
{
	my $message = shift;
	my @attachments = @_;

	foreach my $attachment (@attachments) {
		my ($path, $mime_type) = prepare_attachment($attachment);
		if (not defined($path)) {
			warn("$attachment: File not found. Ignoring.\n");
			next;
		}
		$message->attach(
			Type => $mime_type,
			Path => $path,
			Id   => basename($path),
		);
	}
}

sub mime_message($$)
{
	my ($type, $data) = @_;
	## MIME::Lite doesn't allow setting Type and Data once the 
	## object is created. Well, maybe it does but I don't know how.
	my $message = MIME::Lite->new(
		Type	=> $type,
		Data	=> $data);
	return $message;
}

sub build_message
{
	my $body_inlined;
	my $message;

	if (defined(@attachments_inline)) {
		if (not defined($body_html)) {
			die("Inline attachments (--attach-inline) must be used with --body-html\n");
		}
		$body_inlined = MIME::Lite->new(Type => 'multipart/related');
		$body_inlined->attach(Type => 'text/html', Data => $body_html);
		attach_attachments($body_inlined, @attachments_inline);
		undef($body_html);
	}
	if (defined($body_plain) and (defined($body_html) or defined($body_inlined))) {
		$message = mime_message("multipart/alternative", undef);
		$message->attach(Type => 'TEXT', Data => $body_plain);
		if (defined($body_inlined)) {
			$message->attach($body_inlined);
		} elsif (defined($body_html)) {
			$message->attach(Type => 'text/html', Data => $body_html);
		}

		if (defined(@attachments)) {
			my $message_body = $message;
			$message = mime_message("multipart/mixed", undef);
			$message->attach($message_body);
			attach_attachments($message, @attachments);
		}
	} elsif (defined(@attachments)) {
		if ($#attachments == 0) {
			my ($path, $mime_type) = prepare_attachment($attachments[0]);
			if (not defined($path)) {
				die($attachments[0].": File not found. No other message parts defined. Aborting.\n");
			}
			$message = MIME::Lite->new(
				Type => $mime_type,
				Path => $path);
		} else {
			$message = mime_message("multipart/mixed", undef);
			attach_attachments($message, @attachments);
		}
	} elsif (defined($body_inlined)) {
		$message = $body_inlined;
	} elsif (defined($body_html)) {
		$message = mime_message("text/html", $body_html);
	} elsif (defined($body_plain)) {
		$message = mime_message("TEXT", $body_plain);
	} else {
		$message = mime_message("TEXT", "");
	}

	$message->attr("From" => $from);
	$message->attr("To" => join(", ", @to));
	$message->attr("Subject" => $subject);
	$message->attr("X-Mailer" => "See http://www.logix.cz/michal/devel/smtp");
	#$message->attr("Message-ID" => time()."-".int(rand(999999))."\@smtp-client.pl");
	return $message;
}

sub usage ()
{
	printf (
"Simple SMTP client written in Perl that supports some
advanced features like STARTTLS and AUTH. Can also create 
messages from components (files, text snippets) and attach
files.

Author: Michal Ludvig <michal\@logix.cz> (c) 2003-2008
        http://www.logix.cz/michal/devel/smtp

Usage: smtp-client.pl [--options]

        --host=<hostname>       Host name or address of the SMTP server.
                                (default: localhost)
        --port=<number>         Port where the SMTP server is listening.
                                (default: 25)
        
        --hello-host=<string>   String to use in the EHLO/HELO command.
        --disable-ehlo          Don't use ESMTP EHLO command, only HELO.
        --force-ehlo            Use EHLO even if server doesn't say ESMTP.
        
        Transport encryption (TLS)
        --disable-starttls      Don't use encryption even if the remote 
                                host offers it.
        
        Authentication options (AUTH)
        --enable-auth           Enable all methods of SMTP authentication.
        --auth-login            Enable only AUTH LOGIN method.
        --auth-plain            Enable only AUTH PLAIN method.
        --auth-cram-md5         Enable only AUTH CRAM-MD5 method.
        --user=<username>       Username for SMTP authentication.
        --pass=<password>       Corresponding password.

        Sender / recipient
        --from=<address>        Address to use in MAIL FROM command.
        --to=<address>          Address to use in RCPT TO command. Can be 
                                used multiple times.

        Send a complete RFC822-compliant email message:
        --data=<filename>       Name of file to send after DATA command.
                                With \"--data=-\" the script will read 
                                standard input (useful e.g. for pipes).

        Alternatively build email a message from provided components:
        --subject=<subject>     Subject of the message
        --body-plain=<text|filename>
        --body-html=<text|filename>
                                Plaintext and/or HTML body of the message
                                If both are provided the message is sent
                                as multipart.
        --attach=<filename>[\@<MIME/Type>]
                                Attach a given filename. 
                                MIME-Type of the attachment is guessed 
                                by default guessed but can optionally
                                be specified after '\@' delimiter.
                                For instance: --attach mail.log\@text/plain
                                Parameter can be used multiple times.
                                
        --attach-inline=<filename>[\@<MIME/Type>]
                                Attach a given filename (typically a picture)
                                as a 'related' part to the above 'body-html'. 
                                Refer to these pictures as <img src='cid:filename'>
                                in the 'body-html' contents.
                                See --attach for details about MIME-Type.
                                Can be used multiple times.

        Other options
        --verbose[=<number>]    Be more verbose, print the SMTP session.
        --missing-modules-ok    Don't complain about missing optional modules.
        --help                  Guess what is this option for ;-)
");
	exit (0);
}

