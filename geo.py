import maxminddb

class GEO:
    def __init__(self):
        self.reader = maxminddb.open_database('GeoLite2-City.mmdb')

    def run(self,ip_list):
        locations = []

        for ip in ip_list:
            loc = self.reader.get(ip)
            city = None 
            province = None 
            country = None 
            if loc is None:
                continue
            if "country" in loc and "en" in loc["country"]["names"]:
                country = loc["country"]["names"]["en"]
            elif "registered_country" in loc and "en" in loc["registered_country"]:
                country = loc["registered_country"]["names"]["en"]
            if "subdivisions" in loc and loc["subdivisions"]\
                 and "en" in loc["subdivisions"][0]["names"]:
                 province = loc["subdivisions"][0]["names"]["en"]
            
            if "city" in loc and "en" in loc["city"]["names"]:
                city = loc["city"]["names"]["en"]

            loc_string = ""
            for i in [city,province,country]:
                if len(loc_string) > 0:
                    loc_string += ","
                if i is not None:
                    loc_string += i 
            
            if loc_string not in locations:
                locations.append(loc_string)

        return locations 
