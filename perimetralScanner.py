import re
import os
import getopt, sys


directory = "./files"
output = "resoult.txt"
nmap_type = "-sT "
nmap_port = "--top-ports 100 -Pn"


# Get full command-line arguments
full_cmd_arguments = sys.argv
# Keep all but the first
argument_list = full_cmd_arguments[1:]
short_options = "ho:v"
long_options = ["help", "output=", "verbose"]

try:
    arguments, values = getopt.getopt(argument_list, short_options, long_options)
except getopt.error as err:
    # Output error, and return with an error code
    print (str(err))
    sys.exit(2)

# Evaluate given options
for current_argument, current_value in arguments:
    if current_argument in ("-v", "--verbose"):
        nmap_type = "-sV "
    elif current_argument in ("-h", "--help"):
        print ("Displaying help")
    elif current_argument in ("-o", "--output"):
        #print (("Enabling special output mode (%s)") % (current_value))
        output = str(current_value)

print (output)

os.system("grep -E '[0-9]{1,3}(\.[0-9]{1,3}){3}' " + directory + "/* | grep -Ev '172\.' |perl -nle '/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/ and print $&'  > ./listado_ips.txt")
os.system("cat ./listado_ips.txt | sort | uniq > " + directory + "/ips.txt")
os.system("rm ./listado_ips.txt")
pattern = re.compile("^(?!^0\.)(?!^10\.)(?!^100\.6[4-9]\.)(?!^100\.[7-9]\d\.)(?!^100\.1[0-1]\d\.)(?!^100\.12[0-7]\.)(?!^127\.)(?!^169\.254\.)(?!^172\.1[6-9]\.)(?!^172\.2[0-9]\.)(?!^172\.3[0-1]\.)(?!^192\.0\.0\.)(?!^192\.0\.2\.)(?!^192\.88\.99\.)(?!^192\.168\.)(?!^198\.1[8-9]\.)(?!^198\.51\.100\.)(?!^203.0\.113\.)(?!^22[4-9]\.)(?!^23[0-9]\.)(?!^24[0-9]\.)(?!^25[0-5]\.)(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))$\n")

f = open (directory + '/ips_publicas.txt','w')
for i, line in enumerate(open(directory + '/ips.txt')):
    for match in re.finditer(pattern, line):
        print ('Found on line %s: %s' % (i+1, match.group()))
        valor = match.group()
        f.write (str(valor))
f.close()

os.system( "echo \"\" > " + output)
for i, line in enumerate(open(directory +'/ips_publicas.txt')):
    print (str(line))
    line = line.replace('\n', '').replace('\r', '')
    os.system( "echo Dirección: \"" + line + "\" >> " + output)
    os.system( "whois " + line + " | grep -e role -e address -e abuse-mailbox -e netname -e inetnum >> resultado.txt")
    os.system( "echo \"\" >> resultado.txt")
    os.system( "nmap -n " + nmap_type + nmap_port + " -open " + line + " >> " + output)
    os.system( "echo \"\" >> " + output)
    os.system( "echo \"\" >> " + output)

#os.system( "rm " + directory + "/ips_publicas.txt")
os.system( "rm " + directory + "/ips.txt")
