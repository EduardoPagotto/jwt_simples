'''
Teste de JWT
'''
from datetime import datetime, timedelta

import binascii
import time
import jwt

from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto import Random

class Sifrador(object):
    '''wrapper para facilitar tratamento das chaves'''
    def __init__(self):
        self.key = RSA.generate(1024, Random.new().read)

    def get_public(self):
        '''Retorna chave publica no formato DER'''
        binaria = self.key.publickey().exportKey(format='DER')
        encode = binascii.b2a_base64(binaria)
        return encode.decode('utf_8')

    def get_public2(self):
        '''Retorno a chave publica no formar PEM'''
        nova = self.key.publickey().exportKey(format='PEM', passphrase=None)
        return nova

    def codificar(self, mensagem):
        '''Codifica com a chave publica'''
        binaria = self.key.publickey().encrypt(mensagem, 32)
        encode = binascii.b2a_base64(binaria[0])
        return encode.decode('utf_8')

    def decodigicar(self, sifra):
        '''Decodifica usando chave privada'''
        decode = sifra.encode('utf_8')
        binario = binascii.a2b_base64(decode)
        decodificado = self.key.decrypt(binario)
        return decodificado

#criptografia padrao
def transacao_sifrada_simetrica(dados):
    '''Teste usando chave sincrona SH256'''
    encoded_data = jwt.encode(payload=dados,
                              key='secret',
                              algorithm='HS256',
                              headers={'kid': '230498151c214b788dd97f22b85410a5'})

    print(encoded_data.decode('utf_8'))

    try:
        while True:
            val = jwt.decode(encoded_data,
                             'secret',
                             audience='http://127.0.0.1:5001',
                             algorithms=['HS256'])
            print(val)
            print(val['msg'])
            time.sleep(10)
    except Exception as exp:
        print(exp)


def transacao_msg_sifrada(dados, sifrador):
    '''
    Mesmo que o anterior mas com sifra na mensagem gerada
    por chave publica e aberta por chave privada
    '''

    dados['msg'] = sifrador.codificar('isto esta escondido'.encode('utf_8'))

    encoded_data = jwt.encode(payload=dados,
                              key='secret',
                              algorithm='HS256',
                              headers={'kid': '230498151c214b788dd97f22b85410a5'})

    print(encoded_data.decode('utf_8'))

    try:
        while True:
            val = jwt.decode(encoded_data,
                             'secret',
                             audience='http://127.0.0.1:5001',
                             algorithms=['HS256'])

            print(val)

            print(sifrador.decodigicar(val['msg']))

            time.sleep(10)

    except Exception as exp:
        print(exp)

def transacao_sifrada_assimetrica(dados, sifrador):
    '''
    gera payload com sifra assimetrica
    '''
    # IMPORTANTE
    # Para autenticação a chave privada e usada para criptografar a mensagem de retorno de login
    # A chave publica sera usada para descifrar o retorno.
    # isto acontece na ponta do servidor que ira validar o usuario
    # para a mensagem sifrada o oposto acontece,
    # sendo gerada com chave publica e lida com a chave privada(apenas para usar cifra de teste)
    dados['msg'] = sifrador.codificar('isto esta escondido'.encode('utf_8'))

    chave_privada = sifrador.key.exportKey(format='PEM')
    encoded_data = jwt.encode(payload=dados,
                              key=chave_privada,
                              algorithm='RS256',
                              headers={'kid': '230498151c214b788dd97f22b85410a5'})

    print(encoded_data.decode('utf_8'))

    try:
        while True:
            chave_publica = sifrador.get_public2()
            #chave_publica_texto = chave_publica.decode('utf_8')
            print(chave_publica)

            val = jwt.decode(encoded_data,
                             chave_publica,
                             audience='http://127.0.0.1:5001',
                             algorithms=['HS256', 'RS256'])

            print(val)
            print(sifrador.decodigicar(val['msg']))
            time.sleep(10)

    except Exception as exp:
        print(exp)


if __name__ == '__main__':

    sifrador_assinc = Sifrador()
    dados_payload = {} # PayLoad

    # campos padrao usados na validaçao
    dados_payload['iat'] = datetime.utcnow() # momento da criacao do token (opcional)
    dados_payload['nbf'] = datetime.utcnow() # valido a partir de (opcional)
    dados_payload['exp'] = datetime.utcnow() + timedelta(seconds=20) # expiracao (opcional)
    dados_payload['iss'] = 'http://localhost:5000' # emissor do token (opcional)
    dados_payload['aud'] = ['http://127.0.0.1:5001',
                            'http://127.0.0.1:5002'] # identificacao dos destinatarios (opcional)

    # campos do usuario
    dados_payload['id'] = 1
    dados_payload['senha'] = SHA256.new('senha'.encode('utf_8')).hexdigest()
    dados_payload['usuario'] = SHA256.new('usuario'.encode('utf_8')).hexdigest()
    dados_payload['msg1'] = 'esta mensagem esta aberta no payload'

    transacao_sifrada_simetrica(dados_payload)
    transacao_msg_sifrada(dados_payload, sifrador_assinc)
    transacao_sifrada_assimetrica(dados_payload, sifrador_assinc)
