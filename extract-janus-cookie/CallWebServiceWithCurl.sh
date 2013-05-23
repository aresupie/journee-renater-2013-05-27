# Usage : ./CallWebServiceWithCurl.sh <login> <pass> <url_ws_protege_par_janus>

# Login Janus
LOGIN=$1

# Mot de passe Janus
RESOURCE=$2

# Recuperation du cookie avec le WS de récupération du cookie
COOKIE=$(curl -k -s -u $LOGIN "http://localhost:13000/jaxrs-service/janus/cookie?url=$RESOURCE")

# Formattage du résultat pour cURL
DATA=$(echo $COOKIE | cut -d';' -f4-5 | tr ';' '=')

# Appel de la ressource avec le cookie
curl -k -b "$DATA" "$RESOURCE"
