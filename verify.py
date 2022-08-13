from configparser import ConfigParser
# importing twilio
file = 'config.properties'
config = ConfigParser()
config.read(file)



account_sid = config['twilio']['account']
auth_token = config['twilio']['token']

from twilio.rest import Client

client = Client(account_sid, auth_token)

''' Change the value of 'from' with the number 
received from Twilio and the value of 'to'
with the number in which you want to send message.'''
message = client.messages.create(
                            from_='+12183074015',
                            body ='123456',
                            to = '+6598994217'
                        )

