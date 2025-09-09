# ipLookup
python IP lookup tool ported from project in lab working with honey pot, previously spun off into LAP Web App with reverse proxy and html5 web interface. This version is portable done in python, can be used with files entirely or STDIN/STDOUT

Welcome to the mass IP lookup! Please follow the configuration options, and submit a list, or file with IP addresses!

Options:
  --help              Show this help message
  --file, -f          Input file of IPs separated by line
  --sleep, -s         Time (in seconds) to sleep between queries
  --api               Your API key(s). Comma-separated if multiple (rotates automatically)
  --disposition, -d   Show disposition
  --country, -c       Show country
  --provider, -p      Show provider

  ==== EXAMPLE OUTPUT ====

8.8.8.8 country=US      asn=15169, isp=GOOGLE
4.4.4.4 country=US      asn=3356, isp=LEVEL3
127.0.0.1       country=None    asn=None, isp=None
