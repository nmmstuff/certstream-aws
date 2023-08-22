import sys
import json
import whois
import datetime

domainarg = 'amazon.com'
domainarg = sys.argv[1]

def whois_data(domain):
    df = "%Y-%m-%d %H:%M:%S"  #(2002-10-30 00:00:00

    try:
        d = datetime.date.today().strftime(df)
        w = whois.whois(domain)
        dt = datetime.datetime.strptime(d,df)
        print(w)

        if type(w.creation_date) is list:
         cdt = w.creation_date[0]
        else:
         cdt = w.creation_date

        if type(w.updated_date) is list:
         cdu = w.updated_date[0]
        else:
         cdu = w.updated_date
        print(cdu.strftime("%m/%d/%Y"))

        delta = dt - cdu

    except Exception:
        result = "Domain: " + domain + " CDt: unknown CDu: unknown Delta: unknown" 
        return result

    else:
        result = "Domain: " + domain + " CDt: " + cdt.strftime("%m/%d/%Y") + " CDu: " + cdu.strftime("%m/%d/%Y") + " Delta: " + str(delta.days)
        return result

print(whois_data(domainarg))

