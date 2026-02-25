from zeep import Client
from zeep.transports import Transport
from zeep.plugins import HistoryPlugin
import requests

WSDL = "https://wyszukiwarkaregon.stat.gov.pl/wsBIR/wsdl/UslugaBIRzewnPubl-ver11-prod.wsdl"
API_KEY = ""

session = requests.Session()
transport = Transport(session=session, timeout=20)

history = HistoryPlugin()
client = Client(wsdl=WSDL, transport=transport, plugins=[history])

# 1) login, w BIR zwykle metoda nazywa się Zaloguj
sid = client.service.Zaloguj(API_KEY)
print("SID:", sid)

# 2) ustawienie nagłówka sesji, w usługach GUS zwykle jest to nagłówek o nazwie sid
client.set_default_soapheaders({"sid": sid})

# tutaj dopiero kolejne wywołania typu wyszukiwanie po NIP
