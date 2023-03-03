from django.shortcuts import render, redirect
from django.contrib.auth.models import User, auth
from django.contrib import messages
from .models import Details
from bitcoin import *
import bs4
import requests
from mnemonic import Mnemonic
from web3 import Web3
import json
from django.http import HttpResponseRedirect
import secrets
from sha3 import keccak_256
from coincurve import PublicKey
import uuid
from django.db import models
from requests.exceptions import HTTPError
from requests_toolbelt.utils import dump

# Create your views here.
def index(request):

    if request.method == 'POST':
        addr = request.POST['addr']
        #res2 = requests.get('https://cryptowat.ch/')
        ##res2 = requests.get('https://cryptowat.ch/charts/KRAKEN:ETH-USD')
        ##soup2 = bs4.BeautifulSoup(res2.text, 'lxml')
        #
        #live_price = soup2.find_all('span', {'class': 'price'})
        ##live_bitcoin_price = soup2.find_all(name='div', class_='price-ticker')[1].find("span").text
        ##live_bitcoin_price1 = soup2.find_all(name='div', class_='price-ticker')[1].find("span").text
        #
        #print(live_price)
        #
        #live_bitcoin_price = live_price[0].getText()
        #live_bitcoin_price = list(live_price[0]).find("span").text
        #tes account
        #TESTTT
        #
        #live_bitcoin_price1 = live_price[0].getText()
        #live_bitcoin_price1 = list(live_price[0]).find("span").text
        res = requests.get('https://www.blockchain.com/eth/address/'+addr)
        
        if res:
            soup = bs4.BeautifulSoup(res.text, 'lxml')
            # bal = soup.find_all('span', {'class': 'sc-1ryi78w-0 bFGdFC sc-16b9dsl-1 iIOvXh u3ufsr-0 gXDEBk'})
            bal = soup.find_all('span', {'class': 'sc-1ryi78w-0 cILyoi sc-16b9dsl-1 ZwupP u3ufsr-0 eQTRKC'})
            bal[4].getText()
            final_bal = bal[4].getText()
            final_bal1 = final_bal.replace(" ", "").rstrip()[:-3].upper()
            transactions = bal[3].getText()
            total_received = bal[6].getText()
            total_received1 = total_received.replace(" ", "").rstrip()[:-3].upper()
            total_sent = bal[5].getText()
            total_sent1 = total_sent.replace(" ", "").rstrip()[:-3].upper()
            final_bal1_int = float(final_bal1)
            #total_received1_int = float(total_received1)
            total_received1_int = str(total_received1)
            #total_sent1_int = float(total_sent1)
            total_sent1_int = str(total_sent1)
            
            #key_ref_id = uuid.uuid1()
            #key_ref_id = key_ref_id.hex
            #live_bitcoin_price1_int = float(live_bitcoin_price1)
            
            ##balance_usd = final_bal1_int*live_bitcoin_price1_int
            ##total_received_usd = total_received1_int*live_bitcoin_price1_int
            ##total_sent_usd = total_sent1_int*live_bitcoin_price1_int

            ##balance_usd = final_bal1_int*2
            ##total_received_usd = total_received1_int*2
            ##total_sent_usd = total_sent1_int*2
        else:
            return redirect('/')
        detail = Details()
        detail.balance = final_bal
        detail.balance1 = final_bal1
        detail.transactions = transactions
        detail.total_received = total_received
        detail.total_received1 = total_received1
        detail.total_sent = total_sent
        detail.total_sent1 = total_sent1
        
        asset_by_custID = 'http://localhost:8080/digitalAsset/assetByCustId/'+ addr
        headers = {'Content-type':'application/json', 'Accept':'application/json'}
        #data1 = {"customerId": 1, "assetSerialNo": 1}
        asset_by_custID_response = requests.post(asset_by_custID,  headers=headers)
        asset_by_custID_response.raise_for_status()
        #data = {"customerId": 1, "assetSerialNo": 2,m": "Ether", "assetQuantity": 1, "publicKey": address, "privateKey": private_key, "guid" : key_ref_id})
        asset_retrieve_json = asset_by_custID_response.json()
        private_key_retrieved = asset_retrieve_json["privateKey"]
        detail.private_key_retrieved = private_key_retrieved
        #try:
        #    asset_by_custID = 'http://localhost:8080/digitalAsset/assetByCustId'
        #    #response = requests.post(digi_locker,
        #    #data = {'key1':'value1'})
        #    asset_by_custID_response = requests.post(asset_by_custID,
        #    data = {"customerId": 1, "assetSerialNo": 2 })
        #    asset_by_custID_response.raise_for_status()
        #    #data = {"customerId": 1, "assetSerialNo": 2,m": "Ether", "assetQuantity": 1, "publicKey": address, "privateKey": private_key, "guid" : key_ref_id})
        #    asset_retrieve_json = asset_by_custID_response.json()
        #    private_key_retrieved = asset_retrieve_json["privateKey"]
        #    #privatekey_save = Details( private_key=private_key_retrieved)
            #privatekey_save.save()
        #except HTTPError as http_err:
        #    print(f'HTTP error occurred: {http_err}')
        #except Exception as err:
        #    print(f'Other error occurred: {err}')
        
        

        
        #detail.live_bitcoin_price = live_bitcoin_price
        ##detail.live_bitcoin_price = 2
        #detail.live_bitcoin_price1 = live_bitcoin_price1
        ##detail.live_bitcoin_price1 = 2
        ##detail.balance_usd = int(balance_usd)
        ##detail.total_received_usd = int(total_received_usd)
        ##detail.total_sent_usd = int(total_sent_usd)

    else:
        detail = '   '

    return render(request, 'index.htm', {'detail' : detail})

def login(request):

    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        user = auth.authenticate(username=username, password=password)

        if user is not None:
            auth.login(request, user)
            return redirect('/')
        else:
            messages.info(request, 'Invalid Credentials')
            return redirect('login')

    else:
        return render(request, 'login.htm')

def register(request):
    #detail = Details()
    #private_key = random_key()
    #public_key = privtopub(private_key)
    #address = pubtoaddr(public_key)
    #detail.private_key = private_key
    #detail.public_key = public_key
    #detail.address = address

    detail = Details()
    mnemo = Mnemonic("english")
    words = mnemo.generate(strength=256)
    seed = mnemo.to_seed(words, passphrase="")
    MAIN_NET_HTTP_ENDPOINT = "https://mainnet.infura.io/v3/6d567e46d9cb40b5b67b073b07882f06"
    w3 = Web3(Web3.HTTPProvider(MAIN_NET_HTTP_ENDPOINT))
    account = w3.eth.account.privateKeyToAccount(seed[:32])
    #private_key = account.privateKey
    private_key = keccak_256(secrets.token_bytes(32)).digest()
    #private_key = private_key.hex()
    #public_key = account.address
    #public_key = []
    public_key = PublicKey.from_valid_secret(private_key).format(compressed=False)[1:]

    #public_key - public_key.encode('ascii')
    address = keccak_256(public_key).digest()[-20:]
    address = '0x' + address.hex()
    detail.private_key = private_key.hex()
    detail.public_key = public_key
    detail.address = address
    global key_ref_id
    key_ref_id = uuid.uuid1()
    key_ref_id = key_ref_id.hex
    detail.key_ref_id = key_ref_id
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        password2 = request.POST['password2']
        private_key = request.POST['private_key']
        public_key = request.POST['public_key']
        address = request.POST['address']

        if password==password2:       
            if User.objects.filter(email=email).exists():
                messages.info(request, 'Email Taken')
                return redirect('register')
            elif User.objects.filter(username=username).exists():
                messages.info(request, 'Username Taken')
                return redirect('register')
            else:
                user = User.objects.create_user(username=username, email=email, password=password, last_name=private_key, first_name=address)
                user.save();
                #digi_locker = 'https://pythonexamples.org/'
                digi_locker1 = "http://localhost:8080/digitalAsset/addAsset"
                #response = requests.post(digi_locker,
                #data = {'key1':'value1'})
                #headers = {'Content-type':'application/json', 'Accept':'application/json'}
                private_key_25 = private_key[:25]
                public_key_25 = address[:25]
                head = {'accept': 'application/json', 'Content-Type': 'application/json'}
                #data2 = { 'customerId': 7, 'assetSerialNo': 8, 'assetType': 'crypto', 'assetSource': 'Ether', 'assetEcosystem': 'Ether', 'assetQuantity': 1, 'publicKey': '0x71C7656EC7ab', 'privateKey': '0x71C7656EC7'}
                #data2 = { 'customerId': 1, 'assetSerialNo': 1, 'assetType': 'crypto', 'assetSource': 'Ether', 'assetEcosystem': 'Ether', 'assetQuantity': 1, 'publicKey': address , 'privateKey': private_key}
                data2 = { 'username': username , 'email': email , 'keyRefId': key_ref_id ,  'publicKey': address , 'privateKey': private_key , 'assetType': 'Ether'}
                response1 = requests.post(digi_locker1, json=data2, headers=head, verify=False)
                response1.raise_for_status()
                #response1.raise_for_status()
                #data = {"customerId": 1, "assetSerialNo": 2, "assetType" :"crypto", "assetSource": "Ether", "assetEcosystem": "Ether", "assetQuantity": 1, "publicKey": "0x71C7656EC7ab88b098defB751B7401B5f6d8976F", "privateKey": "0x71C7656EC7ab88b098defB751B7401B5f6d8976F", "guid" :"testguid1"})
            
                #data = {"customerId": 1, "assetSerialNo": 2, "assetType" :"crypto", "assetSource": "Ether", "assetEcosystem": "Ether", "assetQuantity": 1, "publicKey": address, "privateKey": private_key, "guid" : key_ref_id})
                #status_json = dump.dump_all(response1)
            
                #status1 = status_json.decode()
                status1 = response1.text

                keyid_save = Details(key_ref_id=key_ref_id, username=username, email=email, public_key=address, status=status1)
                keyid_save.save()
                print('User Created')
                return redirect('login')

        else:
            messages.info(request, 'Password Not Matching')
            return redirect('register')
        return redirect('/')

    else:
        return render(request, 'register.htm', {'detail': detail})

    

def logout(request):
    auth.logout(request)
    return redirect('/')

#def retrive(request, id):
#    try:
#            asset_by_custID = 'http://localhost:8080/digitalAsset/assetByCustId'
#            #response = requests.post(digi_locker,
#            #data = {'key1':'value1'})
#            asset_by_custID_response = requests.post(asset_by_custID,
#            data = {"customerId": 1, "assetSerialNo": 2 })
#            asset_by_custID_response.raise_for_status()
#            #data = {"customerId": 1, "assetSerialNo": 2,m": "Ether", "assetQuantity": 1, "publicKey": address, "privateKey": private_key, "guid" : key_ref_id})
#            asset_retrieve_json = asset_by_custID_response.json()
#            private_key_retrieved = asset_retrieve_json["privateKey"]
#            #privatekey_save = Details( private_key=private_key_retrieved)
#           #privatekey_save.save()
#    except HTTPError as http_err:
#            print(f'HTTP error occurred: {http_err}')
#    except Exception as err:
#            print(f'Other error occurred: {err}')