#!/usr/bin/perl
#
# Sean's SUPER Regular Expression-Based ABNF Extractor, for XML content
# Sean Leonard <dev+ietf@seantek.com>
# September 28, 2016
# (c) 2016 Sean Leonard of SeanTek(R)
#

use strict;
use warnings;
use 5.012;  # how low should we go?
# use feature 'unicode_strings'; see above
use Getopt::Long qw(GetOptions);
use Pod::Usage qw(pod2usage);
use XML::LibXML;
use XML::LibXML::Reader;
use XML::LibXML::Error;
use encoding::warnings 'FATAL';
use open IN => ":raw";

our $VERSION = '1.997spre';

my $man = 0;
my $help = 0;
my $linecomments = 0;
my $captioncomments = 0;
my $parse_xml = 0;
my $parse_text = 0;

Getopt::Long::Configure qw(bundling auto_version);

GetOptions('help|?' => \$help, man => \$man, 'linecomments|l' => \$linecomments, 'captioncomments|c' => \$captioncomments,
           'xml|x' => \$parse_xml, 'text|t' => \$parse_text) or pod2usage(2);
pod2usage(1) if $help;
pod2usage(-exitval => 0, -verbose => 2) if $man;

if (scalar @ARGV > 1) {
  say STDERR "Too many arguments";
  pod2usage(2);
}

=pod

=head1 NAME

reaex - Sean's SUPER Regular Expression-Based ABNF Extractor

=head1 SYNOPSIS

reaex.pl [options] [input]

Options:
  -l, --linecomments    emit line comments
  -c, --captioncomments emit caption comments
  -x, --xml             parse as XML (xml2rfc)
  -t, --text            parse as plain text
  -?, --help            brief help message
  --man                 full documentation
  --version             version information

Only zero or one input arguments are allowed; STDIN
is used if an input argument is
not specified. Output is to STDOUT, and is always
in UTF-8 with CRLF line endings and no byte order mark.

=head1 OPTIONS

=over 4

=item B<-l>, B<--linecomments>

Emit line comments in the output ABNF, such as the
following for plain text and XML inputs:

  ; lines 99-150 [Pages 2-3]

  ; fig-abnf at lines 99-150

=item B<-c>, B<--captioncomments>

Emit caption comments in the output ABNF, such as:

  ; 4.  Core Rules

If both line and caption comments
are enabled (e.g., B<-lc>), the caption will follow
the lines, delimited by a colon, such as:

  ; lines 99-150 [Pages 2-3]: 4.  Core Rules

=item B<-x>, B<--xml>

Parse the input as XML (xml2rfc). This tool looks for
S<<artwork>> and S<<sourcecode>> elements that
have the type attribute set to "abnf"
(ABNF conformance required), as well
as those that have no type attribute or an empty
type attribute (ABNF is searched in the artwork
or sourcecode text content).

=item B<-t>, B<--text>

Parse the input as plain text in UTF-8
(traditional RFC format ca. 2016) with
arbitrary CRLF or LF line endings. This tool
looks for blocks of ABNF
that are separated by at least one blank line
on either end.

=item B<-?>, B<--help>

Print a brief help message and exit.

=item B<--man>

Print the manual page and exit.

=item B<--version>

Print the version and exit.

=back

=head1 DESCRIPTION

This Regular Expression-Based ABNF Extractor will read
the given input file and output the ABNF that is found
therein. The ABNF must conform to RFC 2234,
RFC 4234, or RFC 5234 (as amended, e.g., by RFC 7405).

The program accepts XML (xml2rfc) and plain text
(traditional RFC format ca. 2016) input formats.
The XML must be well-formed and require no external DTDs
or other substitutions. Unless only one of --text and --xml
are specified, the program will try to parse
the input as XML first; if an XML document
is not found ("document is empty" or
"extra content at the end of the document"), then
the program will try to parse the input as plain text.

This program takes a non-heuristic view
as to what constitutes ABNF, based on strict
interpretations of the ABNF RFCs. It does not attempt to
recognize or repair broken ABNF, leaving those jobs
to other processes.

=head1 EXIT STATUS

The program exits 0 on success, and >0 if an error
occurs.

Generic statuses:

 81  no Reference(s) section(s) found
 82  no ABNF reference found (2234, 4234, 5234, 7405)
 83  no ABNF rules found

XML only: 

 84  unsupported src attribute found on a candidate element
 85  a candidate ABNF-only element is not entirely ABNF

Other exit codes are possible based on the underlying
libraries, such as libxml2.

=head1 AUTHOR

Sean Leonard of SeanTek(R) <dev+ietf@seantek.com>

=cut

binmode STDOUT, ":utf8";

# for de-paginating RFC content
my $PAGEBREAK = qr/(?:\r\n){3}(\r\n(?:\r\n)?)(?>(?:\r\n)*)[^\r\n]{70}[0-9]\]\r\n\f\r\n[^\r\n]{68}[0-9]{4}(?:\r\n){3}/;

# for ABNF
my $ABNFRE = qr/(?(DEFINE)
 (?<rule>(?&rulename)(?&defined_as)(?&elements)(?&c_nl))
 (?<rulename>[A-Za-z][\-0-9A-Za-z]*)
 (?<defined_as>(?&c_wsp)*=\/?(?&c_wsp)*)
 (?<elements>(?&alternation)(?&c_wsp)*)
 (?<c_wsp>(?&c_nl)?[\t ])
 (?<c_nl>(?:;[\t -~\N{U+A0}-\x{2027}\x{202A}-\x{D7FF}\x{E000}-\x{FDCF}\x{FDF0}-\x{FFFD}\x{10000}-\x{1FFFD}\x{20000}-\x{2FFFD}\x{30000}-\x{3FFFD}\x{40000}-\x{4FFFD}\x{50000}-\x{5FFFD}\x{60000}-\x{6FFFD}\x{70000}-\x{7FFFD}\x{80000}-\x{8FFFD}\x{90000}-\x{9FFFD}\x{A0000}-\x{AFFFD}\x{B0000}-\x{BFFFD}\x{C0000}-\x{CFFFD}\x{D0000}-\x{DFFFD}\x{E0000}-\x{EFFFD}\x{F0000}-\x{FFFFD}\x{100000}-\x{10FFFD}]*)?\r\n)
 (?<alternation>(?&concatenation)(?:(?&c_wsp)*\/(?&c_wsp)*(?&concatenation))*)
 (?<concatenation>(?&repetition)(?:(?&c_wsp)+(?&repetition))*)
 (?<repetition>(?&repeat)?(?&element))
 (?<repeat>[0-9]+|[0-9]*\*[0-9]*)
 (?<element>(?&rulename)|(?&group)|(?&option)|(?&char_val)|(?&num_val)|(?&prose_val))
 (?<group>\((?&c_wsp)*(?&alternation)(?&c_wsp)*\))
 (?<option>\[(?&c_wsp)*(?&alternation)(?&c_wsp)*\])
 (?<char_val>(?>(?&case_insensitive_string)|(?&case_sensitive_string)))
 (?<case_insensitive_string>(?:%[Ii])?(?&quoted_string))
 (?<case_sensitive_string>%[Ss](?&quoted_string))
 (?<quoted_string>"[ !#-~]*")
 (?<num_val>%(?>(?&bin_val)|(?&dec_val)|(?&hex_val)))
 (?<bin_val>[Bb][01]+(?:(?:\.[01]+)+|-[01]+)?)
 (?<dec_val>[Dd][0-9]+(?:(?:\.[0-9]+)+|-[0-9]+)?)
 (?<hex_val>[Xx][0-9A-Fa-f]+(?:(?:\.[0-9A-Fa-f]+)+|-[0-9A-Fa-f]+)?)
 (?<prose_val><[ -=?-~]*>)
)/;

local $/ = undef;

my $data = <> || die;
open my $fh, "< :scalar", \$data or die; # :raw is already implied

goto PARSE_AS_TEXT if ($parse_text && !$parse_xml);

# PARSE AS XML

PARSE_AS_XML:
my $reader = XML::LibXML::Reader->new(IO => $fh, line_numbers => 1, suppress_errors => 0);
my $pres = $reader->preservePattern('*');

my $res = "XXX";

my $eres = eval { $res = $reader->finish; };

if (ref($@)) {
  our $error_domain = $@->domain();
  our $error_code = $@->code();
  our $error_level = $@->level();

  # see XML 1.0 Fifth Ed. (2008), [1] document
  if ($error_level == XML::LibXML::Error::XML_ERR_FATAL and # 3
      $error_domain eq "parser" and
      $error_code == 4 || $error_code == 5 and # xmlParserErrors XML_ERR_DOCUMENT_EMPTY || XML_ERR_DOCUMENT_END
      not ($parse_xml && !$parse_text)) { # when --xml only asserted, all errors are fatal
    $@ = undef;
    goto PARSE_AS_TEXT;
  } else {
    die;
  }
} elsif ($@) {
  die;
}

# my $parser = XML::LibXML->new($linecomments ? {line_numbers => 1} : {});
# my $xmldoc = $parser->parse_file($ARGV[0]);

my $xmldoc = $reader->document;

my $back = $xmldoc->findnodes('/rfc/back[references]');
unless ($back->size() == 1) { # and has one node
  say STDERR "No References section found";
  exit 81;
}
$back = $back->get_node(0);

# be aware that STD and RFC are case sensitive; see stackoverflow.com/questions/1625446 for translate hack
unless ($back->exists(q{//reference/seriesInfo[(@name='STD' and @value='68') or (@name="RFC" and (@value="5234" or @value="7405" or @value="4234" or @value="2234"))]})) {
  say STDERR "No reference to ABNF standards found";
  exit 82;
}

my @blocks = $xmldoc->findnodes(q{/rfc//*[(self::artwork or self::sourcecode) and (@type='abnf' or @type='' or not(@type))]});

my @figs;
if ($captioncomments) {
  @figs = $xmldoc->findnodes('//figure');
}

my $counter = 0;

foreach (@blocks) {
  # this tool expects ABNF to be inline only
  if (length $_->getAttribute('src')) {
    print STDERR "<", $_->nodeName, ">";
    if ($linecomments) {
      my $line_start = $_->previousSibling() ? $_->previousSibling()->line_number() : $_->parentNode->line_number();
      print " at line ", $line_start;
    }
    say ' has a @src attribute, which is not supported';
    exit 84;
  }

  my $text = $_->textContent;
  # normalize line endings
  $text =~ s/\r\n?|\n/\r\n/g;

  $text .= "\r\n" if ("\r\n" ne substr $text, -2);
  
  if ($_->hasAttribute('type') and $_->getAttribute('type') eq 'abnf') {
    # confirm that it's ABNF and only ABNF
    # starts with nonproductive line(s)* then WSP rule etc. then nonproductive lines*
    unless ($text =~ /$ABNFRE^(?:(?:[\t ]*(?&c_nl))*[\t ]*(?&rule))+(?:[\t ]*(?&c_nl))*$/) {
      print STDERR "<", $_->nodeName;
      print ' anchor="', $_->getAttribute('anchor'), '"' if ($_->hasAttribute('anchor'));
      print ' type="abnf">';
      if ($linecomments) {
        # compute line numbers (based on end of start tag): previous node's line number is start of subject node
        my $line_start = $_->previousSibling() ? $_->previousSibling()->line_number() : $_->parentNode->line_number();
        my $line_end = $_->line_number();

        print $line_end == $line_start ? " at line $line_start" : " at lines $line_start-$line_end";        
      }
      say ' is not actually ABNF';
      exit 85;
    }
  } else {
    # hunt for ABNF blocks (could be interspersed)
    my $match_block = "";
    my $sub_matches = 0;
    while ($text =~ /$ABNFRE(?:^|(?<=\r\n))(?:(?:[\t ]*(?&c_nl))*[\t ]*(?&rule))+(?:[\t ]*(?&c_nl))*/g) {
      # trim leading and trailing white lines (which might have embedded WSP, but not comments)
      # white line: wl = *WSP CRLF
      my $match_one = $&;
      $match_one =~ s/^(?:[\t ]*\r\n)*//;
      $match_one =~ s/([\t ]*\r\n)(?:[\t ]*\r\n)*$/$1/;
      $match_block .= $match_one; # always going to end with CRLF
      $sub_matches++;
    }
    next unless $sub_matches;
    $text = $match_block;
  }

  print "\r\n" if ($counter > 0);

  if ($linecomments) {
    my $artwork_anchor = $_->getAttribute('anchor');
    unless (length $artwork_anchor and $artwork_anchor =~ /^[:A-Z_]/i) {
      $artwork_anchor = $_->parentNode->getAttribute('anchor') if $_->parentNode->nodeName eq 'figure';
    }
    print '; ';
    if (length $artwork_anchor and $artwork_anchor =~ /^[:A-Z_]/i) {
      print $artwork_anchor, ' at ';
    }
    
    # compute line numbers (based on end of start tag): previous node's line number is start of subject node
    my $line_start = $_->previousSibling() ? $_->previousSibling()->line_number() : $_->parentNode->line_number();

    # when no children, subject node is the last line number, cuz it's empty
    my $line_end;
    unless ($_->lastChild) {
      $line_end = $_->line_number();
    } else {
      # pathological case of <![CDATA[ ...CRLF...]]></artwork> where line_number() counts
      # at <![CDATA[ instead of ]]>. So need to count internal lines. Also,
      # adjoining CDATA sections get merged!
      $line_end = $_->lastChild->line_number();
      if ($_->lastChild->nodeType == XML_CDATA_SECTION_NODE) {
        my $lcd = $_->lastChild->data;
        my $cdata_lines = () = $_->lastChild->data =~ /\n/g;
        $line_end += $cdata_lines;
      }
    }

    print $line_end == $line_start ? "line $line_start" : "lines $line_start-$line_end";
  }

  if ($captioncomments) {
    my $caption;
    my $figure = $_->parentNode;
    #      Figure X: Foo ABNF
    if ($figure->nodeName eq 'figure') {
      my $name = $figure->firstChild;
      while ($name) {
        if ($name->nodeName eq 'name') {
          $caption = name->textContent;
          last;
        }
        $name = $name->nextSibling();
      }
      $caption = $figure->getAttribute('title') unless (length $caption);
      my $figure_anchor = $figure->getAttribute('anchor');
      if (length $figure_anchor and $figure_anchor =~ /^[:A-Z_]/i) {
        my $figure_count = 1;
        foreach my $fig (@figs) {
          last if ($fig == $figure);
          my $fig_anchor = $fig->getAttribute('anchor');
          $figure_count++ if (length $fig_anchor and $fig_anchor =~ /^[:A-Z_]/i);
        }
        $caption = 'Figure ' . $figure_count . (length $caption ? ': ' . $caption : '');
      }
    }

    unless (length $caption) {
      #    The following is interesting ABNF:
      my $immediate_prev_sibling = ($figure->nodeName eq 'figure') ? $figure->previousSibling() : $_->previousSibling();
      while ($immediate_prev_sibling) {
        if ($immediate_prev_sibling->nodeType == XML_ELEMENT_NODE) {
          if ($immediate_prev_sibling->nodeName eq 't') {
            my @cn = $immediate_prev_sibling->childNodes();
            # we only handle bare text -- no xref, eref, strong, em, tt, blah blah blah...
            if (1 == scalar @cn and $cn[0]->nodeType == XML_TEXT_NODE) {
              $caption = $cn[0]->data;
              $caption =~ s/[\t ]*(?:\r\n?|\n)[\t ]*/ /g;
              $caption =~ s/^[\t ]+//g;
              $caption =~ s/[\t ]+$//g;
              # no more than approximately one line: 72 chars minus 3 indent spaces = 69
              $caption = '' if (length $caption > 69);
            }
          }
          last;
        }
        $immediate_prev_sibling = $immediate_prev_sibling->previousSibling();
      } # end while backtracking through previous siblings
    }
    
    unless (length $caption) {
      # 6.3. Foo Section ABNF
      
      # looking for ancestor <section> elements, then counting peceding siblings
      my $section = $_;
      while ($section = $section->parentNode) {
        if ($section->nodeName eq 'section') {
          # if it matches, then <name> or @title
          my $section_title = $section->getAttribute('title');
          # count sections (there has to be at least one)
          my @asections = $section->findnodes('./ancestor-or-self::section');
          $caption = '';
          
          if ($asections[0]->parentNode->nodeName eq 'back') {
            my $sec = shift @asections;
            my $sec_num = $sec->findvalue('count(./preceding-sibling::section)');
            
            my $n = $sec_num;
            my @a;
            while ($n >= 0) {
              unshift @a, $n % 26;
              $n = int($n/26) - 1;
            }
            $caption = (join '', map chr(ord('A') + $_), @a) . '.';
            unless (scalar @asections) {
              $caption = 'Appendix ' . $caption;
            }
          } elsif ($asections[0]->parentNode->nodeName ne 'middle') {
            warn 'Top-level ' . $asections[0]->nodePath() . ' is not in <middle> or <back>';
            $caption = '';
            last;
          }
          
          foreach my $sec (@asections) {
            my $sec_count = $sec->findvalue('count(preceding-sibling::section)');
            $caption .= (1 + $sec_count) . '.';
          }
          
          $caption .= '  ' . $section_title if (length $section_title);
          last;
        }
      }
    }
    
    print $linecomments ? ': ' : '; ', $caption if (length $caption);
  }
  print "\r\n\r\n" if ($linecomments || $captioncomments);
  print $text;
  
  $counter++;
} # end iterate over every candidate block

unless ($counter) {
  say STDERR "No ABNF rules found";
  exit 83;
}

exit 0;

# PARSE AS TEXT

PARSE_AS_TEXT:
seek $fh, 0, 0;
binmode $fh, ":encoding(UTF-8)";
my $RFC = <$fh> || die;

# normalize line endings
$RFC =~ s/\r\n?|\n/\r\n/g;

# search for References sections--slurp the pagination while at it
# The trailing dot . does not appear in RFC 3261, RFC 2445, RFC 2550 (4/1), RFC 2640, RFC 2885, RFC 2926!
# Bare "References" appears in RFC 2326, RFC 2327, RFC 2849, RFC 2915, RFC 2919!
# Bare "REFERENCES" appears in RFC 2373!
# Bare "Bibliography" appears in RFC 2967!
# "8:  Referenced Documents" appears in RFC 2743, but irrelevant!

my @references = ($RFC =~ m/(?<=\r\n)(?:(?:R(?:eferences|EFERENCES)|Bibliography)|[1-9A-Za-z][!-~]*[.:]? +(?:Normative +|Informative +)?References?)(?:\r\n)+(?:[^\r\n]{72}\r\n\f\r\n[^\r\n]{72}\r\n|(?:[\t ]+[\t -~]*)?\r\n)*/g);

# No References section found
# want to die with a SPECIFIC exit code
# RFC 2327 will get clobbered: see Errata ID 4804! But it's obsolete; use RFC 4566 instead!
unless (@references) {
  say STDERR "No References section found";
  exit 81;
}

my $refs = join('\r\n', @references);

# search for RFC[\t ]*(?:[245]234|7405), etc.
if ($refs !~ /RFC(?: |\r\n[\t ]+)?(?:[245]234|7405)/) {
  say STDERR "No reference to ABNF standards found";
  exit 82;
}

my $match_count = 0;

# \r\n[\t ]*(?&rulelist)[\t ]*\r\n
# (?<rulelist>(?:(?&rule)|(?&c_wsp)*(?&c_nl))+)
# (?<c_nl>(?&comment)|\r\n)
# (?<c_nl>(?:;[\t -~]*)?\r\n)
# (?<comment>;[\t -~]*\r\n)
# (?<rulelist>(?&rule)(?:(?:\r\n)* *(?&rule))+)
# (?<c_wsp>[\t ]|(?&c_nl)[\t ])
# (?<rulelist>(?&rule)(?:(?:[\t ]|(?&c_nl))*(?&rule))+)
# \r\n\r\n *(?&rulelist)\r\n
# (?<npl>[\t ]*(?&c_nl))   nonproductive line: npl = *WSP c-nl
# rfcrulelist = 1*(*npl *WSP rule) *npl
# isolate and output ABNF rulelists
# RFC 3261 has examples that will confuse just one CRLF up front,
# so I guess 2CRLF up front is the way to go.
while ($RFC =~ /(?(DEFINE)
 (?<rule>(?&rulename)(?&defined_as)(?&elements)(?&c_nl))
 (?<rulename>[A-Za-z][\-0-9A-Za-z]*)
 (?<defined_as>(?&c_wsp)*=\/?(?&c_wsp)*)
 (?<elements>(?&alternation)(?&c_wsp)*)
 (?<c_wsp>(?&c_nl)?[\t ])
 (?<c_nl>(?:;[\t -~\N{U+A0}-\x{2027}\x{202A}-\x{D7FF}\x{E000}-\x{FDCF}\x{FDF0}-\x{FFFD}\x{10000}-\x{1FFFD}\x{20000}-\x{2FFFD}\x{30000}-\x{3FFFD}\x{40000}-\x{4FFFD}\x{50000}-\x{5FFFD}\x{60000}-\x{6FFFD}\x{70000}-\x{7FFFD}\x{80000}-\x{8FFFD}\x{90000}-\x{9FFFD}\x{A0000}-\x{AFFFD}\x{B0000}-\x{BFFFD}\x{C0000}-\x{CFFFD}\x{D0000}-\x{DFFFD}\x{E0000}-\x{EFFFD}\x{F0000}-\x{FFFFD}\x{100000}-\x{10FFFD}]*)?\r\n(?:(?:\r\n){3}[^\r\n]{70}[0-9]\]\r\n\f\r\n[^\r\n]{68}[0-9]{4}(?:\r\n){3})?)
 (?<alternation>(?&concatenation)(?:(?&c_wsp)*\/(?&c_wsp)*(?&concatenation))*)
 (?<concatenation>(?&repetition)(?:(?&c_wsp)+(?&repetition))*)
 (?<repetition>(?&repeat)?(?&element))
 (?<repeat>[0-9]+|[0-9]*\*[0-9]*)
 (?<element>(?&rulename)|(?&group)|(?&option)|(?&char_val)|(?&num_val)|(?&prose_val))
 (?<group>\((?&c_wsp)*(?&alternation)(?&c_wsp)*\))
 (?<option>\[(?&c_wsp)*(?&alternation)(?&c_wsp)*\])
 (?<char_val>(?>(?&case_insensitive_string)|(?&case_sensitive_string)))
 (?<case_insensitive_string>(?:%[Ii])?(?&quoted_string))
 (?<case_sensitive_string>%[Ss](?&quoted_string))
 (?<quoted_string>"[ !#-~]*")
 (?<num_val>%(?>(?&bin_val)|(?&dec_val)|(?&hex_val)))
 (?<bin_val>[Bb][01]+(?:(?:\.[01]+)+|-[01]+)?)
 (?<dec_val>[Dd][0-9]+(?:(?:\.[0-9]+)+|-[0-9]+)?)
 (?<hex_val>[Xx][0-9A-Fa-f]+(?:(?:\.[0-9A-Fa-f]+)+|-[0-9A-Fa-f]+)?)
 (?<prose_val><[ -=?-~]*>)
)\r\n\r\n(?:(?:[\t ]*(?&c_nl))*[\t ]*(?&rule))+(?:[\t ]*(?&c_nl))*\r\n/g) {
  # $total_matches++;
  my $match_thing = $&; # always going to start and end with CRLF
  my $match_before = $`;
  my $match_after = $';
  $match_count++;
  
  if ($linecomments) {
    my $lines_before = () = $match_before =~ /\r\n/g;
    $lines_before += 2;
    my $lines_inside = () = $match_thing =~ /\r\n/g;
    my $lines_end = $lines_before + $lines_inside - 2;
    print "; lines $lines_before-$lines_end";
        
    my $page_start = 1;
    my $last_FRN = rindex $match_before, "\f\r\n";
    if ($last_FRN != -1) {
      my $last_LSB = rindex $match_before, '[', $last_FRN;
      if ($last_LSB != -1) {
        my $page_block = substr $match_before, $last_LSB + 1, $last_FRN - $last_LSB - 1;
        $page_start = int($1) + 1 if ($page_block =~ /^Page ([1-9][0-9]*)\]\r\n$/);
      }
    }
    my $page_end = $page_start;
    $page_end = int($1) if ($match_after =~ /\[Page ([1-9][0-9]*)\]\r\n(?:\f\r\n|$)/);
    print $page_start == $page_end ? " [Page $page_start]" : " [Pages $page_start-$page_end]";    
  }

  if ($captioncomments) {
    # scan for captions
    my $possible_caption = '';
    #     Figure 3: Foo ABNF
    #             ?????????? (optional)
    # (followed by blank line)
    # $match_after =~ /^( (?>([!-9;-~](?:[ -~]*[!-9;-~])?: [ -~]+[!-~])|(?1))+ )\r\n/;

    if ($match_after =~ /^( *)([!-9;-~](?:[ -~]*[!-9;-~])?(?:: [ -~]+[!-~])?) *\r\n[\t ]*\r\n/) {
      my $counting = 2*(length $1) + length $2;
      $possible_caption = $2 if ($counting == 74 || $counting == 75);
    }

    unless (length $possible_caption) {
      #    The following is interesting ABNF:
      $match_before =~ s/$PAGEBREAK/$1/g;
      if ($match_before =~ /\r\n\r\n( {3,})([!-~](?:[ -~]*[!-~])?) *$/) {
        my $counting = 2*(length $1) + length $2;
        # Do not accept if the prior line is center-aligned, as it's probably a caption for the prior figure
        $possible_caption = $2 unless ($counting == 74 || $counting == 75);
      }
    }
    
    unless (length $possible_caption) {
      # 6.3. Foo Section ABNF
      # need to use single-line mode so . matches everything
      if ($match_before =~ /.*\r\n\r\n([1-9A-Za-z][!-~]*[.:]?)( +)([!-~](?:[ -~]*[!-~])?(?: *\r\n {2,}[!-~](?:[ -~]*[!-~])?)*) *(?:$|\r\n\r\n)/s) {
        # affirm spacing
        my $prelength = (length $1) + (length $2);
        my @lines = split /\r\n/, $3;
        $possible_caption = $1 . $2 . shift @lines;
        foreach my $line (@lines) {
          last unless ($line =~ /^ {$prelength}([!-~](?:[ -~]*[!-~])?)/);
          $possible_caption .= " " . $1;
        }
      }
    }
    
    if (length $possible_caption) {
      print $linecomments ? ":" : ";", " ", $possible_caption, "\r\n";
    } else {
      print "\r\n" if $linecomments;
    }
  } else {
    print "\r\n" if $linecomments;
  }

  # de-paginate here. By doing it here, it keeps the line counts accurate.
  $match_thing =~ s/$PAGEBREAK/$1/g;
  # chomp leading and trailing bare CRLFs/comment-free lines (except one each)
  $match_thing =~ s/^(?:[\t ]*\r\n){2,}/\r\n/; # only one CRLF allowed (first CRLF not considered part of it)
  $match_thing =~ s/(?:[\t ]*\r\n){3,}$/\r\n\r\n/;

  print $match_thing;
}

unless ($match_count) {
  say STDERR "No ABNF rules found";
  exit 83;
}

exit 0;
