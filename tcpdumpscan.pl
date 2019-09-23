#!/usr/bin/perl
#
#Nascopie
#
#Script en perl permettant de lire un fichier tcpdump et d'en extraire des informations
#Nécessite le nom du fichier texte en ligne de commande (ex: dump.txt)

#vérifie qu'il n'y a qu'un seul paramêtre
if (@ARGV != 1){
	print"Erreur dans les  les paramêtres\n";
	exit 1;
}
#subroutine pour enlever le whitespace du début et de fin
sub trim($)
{
	my $string = shift;
	$string =~ s/^\s+//;
	$string =~ s/\s+$//;
	return $string;
}
#récupération de l'argument passé en ligne de commange
my $file = @ARGV[0];

#on appel les variables d'environnement pour creer une adresse courriel
my $EMAIL = $ENV{'COURRIEL'};

#tableau associatif
my %liste_proto;
my %liste_dest;
my %liste_uid;
my %liste_ip;

#ouverture des fichier passé en paramêtre
open (FICHIER,"<$file") or die "Ne peut pas ouvrir le fichier $file : $! \n";
open (PROTO,">proto.txt") or die "Ne peut pas ouvrir le fichier proto.txt : $! \n";
open (DESTINATION,">destination.txt") or die "Ne peut pas ouvrir le fichier destination.txt : $! \n";
open (NFSUID,">nfsuid.txt") or die "Ne peut pas ouvrir le fichier nfsuid.txt : $! \n";
open MAIL,	"|	/usr/sbin/sendmail	$EMAIL"	or die	"Impossible	d'envoyer un message $! \n";

#lecture du fichier tcpdump
while($ligne=<FICHIER>){
	
	$ligne = trim($ligne);
	#on place les données de la ligne dans des variables	
	my ($no, $heure, $adrSource, $adrDest, $proto, $info) = split /\s+/, $ligne;
	@all = split /\s+/, $ligne;
	
#debut de proto.txt
	if (exists $liste_proto{"$proto"}) {
			#on incremente la valeur du key
			$liste_proto{$proto}++;		
	}
	else{
			#on cree un key avec une valeur initial de 1
			$liste_proto{$proto} = 1 ;
	}
#fin de proto.txt

#debut de destination.txt
	if (exists $liste_dest{"$adrDest"}) {
		#on incremente la valeur du key
		$liste_dest{$adrDest}++;		
	}
	else{
		#on cree un key avec une valeur initial de 1
		$liste_dest{$adrDest} = 1 ;
	}
#fin de destination.txt

#debut de nfsuid.txt
	if ($ligne =~ /GETATTR Reply/ && $ligne =~ /Regular File/) {		
		$uid = @all[14];
		if (exists $liste_uid{"$uid"}){
			$liste_uid{$uid}++;
		}
		else{
			$liste_uid{$uid} = 1;
		}
	}
#fin de nfsuid.txt

#debut de SENDMAIL
	if ($proto eq "ARP" ){
		my $mac;
		#on trouve les reponses retournant une paire IP/MAC
		if($info =~ /\d+.\d+.\d+.\d+/){
			$mac = @all[8];
			if (exists $liste_ip{"$info"}){		
			}
			else{
			$liste_ip{$info} = "$mac";
			}		
		}
	}
#fin de SENDMAIL

	
}
#ecriture des donnees dans le fichier proto.txt
delete $liste_proto{'Protocol'};
foreach my $protocol (keys %liste_proto) {
    print PROTO "$protocol:$liste_proto{$protocol} paquets\n";
}
#ecriture des donnees dans le fichier destination.txty
delete $liste_proto{'Destination'};
foreach my $dest (keys %liste_dest) {
    print DESTINATION "$dest: $liste_dest{$dest} paquets\n";
}
#ecriture des donnees dans le fichier nfsuid.txt
foreach my $user (keys %liste_uid) {
    print NFSUID "$user -> $liste_uid{$user} fois\n";
}
#test
print MAIL "To: <$EMAIL>\n";
print MAIL "From: <$EMAIL>\n";
print MAIL "Subject: Liste des paires IP/MAC du protocole ARP\n";
print MAIL "\n";
print MAIL "Voici les paires IP/MAC retournées par le protocole ARP provenant du fichier $file\n";
print MAIL "\n";
foreach my $pair (sort keys %liste_ip) {
	print MAIL "$pair : $liste_ip{$pair}\n";
}
print MAIL "\n";



#fermeture des fichiesr lu
close(FICHIER);
close(PROTO);
close(DESTINATION);
close(NFSUID);
close MAIL;
exit 0;

