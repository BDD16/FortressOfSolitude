"""
DBA 1337_TECH, AUSTIN TEXAS © MAY 2020
Proof of Concept code, No liabilities or warranties expressed or implied.
"""

# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models

from datetime import datetime
from .cryptoutils import CryptoTools
from base64 import b64encode, b64decode
from django.contrib.auth import get_user_model
from random import random

# Create your models here.

# Constants
LENGTH_OF_KEK = 32  # 256 bits or 32 bytes
LENGTH_OF_DEK = 32  # 256 bits or 32 bytes
LENGTH_OF_SALT = 32  # 256 bits or 32 bytes

'''
KeyMold is a models.Manager clas extension that includes creating a Kek and retrieving a kek
no inputs
'''


class KeyMold(models.Manager):

    def _create_kek(request, **kwargs):
        pwd = request.user.password
        # print("deriving kek")
        self.kek = DeriveKek_default(pwd)
        return self.kek

    def get_queryset(self):
        qs = models.QuerySet(self.model)
        if self._db is not None:
            qs = qs.using('default')
        return qs


'''
TelescopeCoord is a models.Manager that allows to find the neutron star that will be used for the keyMold to make a Key Encryption Key [kek].
no inputs
'''


class TelescopeCoord(models.Manager):
    def get_queryset(self):
        qs = models.QuerySet(self.model)
        if self._db is not None:
            qs = qs.using('default')
        return qs


'''
QuasiPlasma is a models.Manager that allows for deriving Data Encryption Keys [DEKs] and retrieving deks from the neutron stars plasma.
no inputs
'''


class QuasiPlasma(models.Manager):

    def _create_dek(request, **kwargs):
        pwd = request.user.password
        self.dek = DeriveDek_default(pwd)
        return self.dek

    def get_queryset(self):
        qs = models.QuerySet(self.model)
        if self._db is not None:
            qs = qs.using('default')
        return qs


'''
KEK is the Key encryption Key [KEK] model.Model class extension that has the ability to derive a new KEK as well as wrap the KEK.
no inputs
'''


class KEK(models.Model):
    # Never should the key be passed as clear text always use the wrap or unwrap functions
    crypto = CryptoTools()
    kek = None
    wrappedKek = None
    result_wrapped_nonce = models.CharField(max_length=128, default=b64encode(int(55).to_bytes(4, 'big')))
    result_wrapped_kek = models.CharField(max_length=128, default=None)

    objects = TelescopeCoord()

    class Meta:
        verbose_name = 'KEK'

    def unwrap_key(self, password):
        if isinstance(password, str) and self.kek == None and self.wrappedKek == None:
            self.crypto.nonce = b64decode(self.result_wrapped_nonce)
            self.kek = self.crypto.AesDecryptEAX(b64decode(self.result_wrapped_kek),
                                                 self.crypto.Sha256(password.encode()))
            print("WAY OFF BASE")
        if isinstance(password, bytes) and self.kek == None and self.wrappedKek == None:
            if isinstance(self.result_wrapped_nonce, str):
                result_wrapped_nonce = (self.result_wrapped_nonce.encode()).replace(b"b'", b'')
                result_wrapped_nonce = result_wrapped_nonce[:-1]
                result_wrapped_nonce = result_wrapped_nonce + b'=' * (len(self.result_wrapped_nonce) % 4)
                self.crypto.nonce = b64decode(result_wrapped_nonce)
            else:
                self.crypto.nonce = b64decode(self.result_wrapped_nonce)
            # print("wrappedKek: " + self.result_wrapped_kek)
            if isinstance(self.result_wrapped_kek, str):
                result_wrapped_kek = (self.result_wrapped_kek.encode()).replace(b"b'", b'')

                result_wrapped_kek = result_wrapped_kek[:-1]
                print("herewe go:" + str(result_wrapped_kek))
                # self.result_wrapped_kek.encode()
                result_wrapped_kek = result_wrapped_kek + b'=' * (len(result_wrapped_kek) % 4)
            elif isinstance(self.result_wrapped_kek, bytes):
                result_wrapped_kek = self.result_wrapped_kek
            self.kek = self.crypto.AesDecryptEAX(b64decode(result_wrapped_kek), CryptoTools().Sha256(password))


        else:
            try:
                self.crypto.nonce = b64decode(self.result_wrapped_nonce)
                if not isinstance(password, bytes):
                    password = password.encode()
                self.kek = self.crypto.AesDecryptEAX(b64decode(self.result_wrapped_kek), self.crypto.Sha256(password))
                self.wrappedKek = None
            except:
                print('someone has attempted to spoof the KEK (key encryption key)')

        print("UNWRAPPED>KEK")
        print(self.kek)
        return self.kek

    def wrap_key(self, password):
        if isinstance(password, str) and self.kek == None:
            self.kek = self.crypto.AesEncryptEAX(data, self.crypto.Sha256(password.encode()))
            self.wrappedKek = self.kek
            self.kek = None

        elif isinstance(password, bytes) and self.kek == None:
            self.kek = self.crypto.AesEncryptEAX(data, self.crypto.Sha256(password))
            self.wrappedKek = b64encode(self.kek)
            self.kek = None
        elif self.kek != None:
            try:
                # print("ATTEMPTING WRAPPING KEK")
                self.crypto.nonce = b64decode(self.result_wrapped_nonce)
                # print("set nonce")
                if isinstance(password, bytes):
                    self.wrappedKek = b64encode(self.crypto.AesEncryptEAX(self.kek, self.crypto.Sha256(password)))
                else:
                    self.wrappedKek = b64encode(
                        self.crypto.AesEncryptEAX(self.kek, self.crypto.Sha256(password.encode())))

                self.kek = None
            except OSError as ERROR:
                print(ERROR)
                print('Wrapping KEK (key encryption key) was unsuccessful')

        return self.wrappedKek


'''
using the model of KEK unwrap and wrap the kek then unwrap the dek then pass the dek to a more useable object
perhaps this will also fetch the dek that is associated with that data model, so needs to be a manytomany relation.

DEK is a models.Model or Data Encryption Key class that allows to store, derive, and wrap Data Encryption Keys from a KEK and Salt
'''


class DEK(models.Model):
    crypto = CryptoTools()
    dek = None
    wrappedDek = None
    SALT = None
    result_wrapped_nonce = models.CharField(max_length=128, default=b64encode(int(55).to_bytes(4, 'big')))
    result_wrappedDek = models.CharField(max_length=128)

    result_SALT = models.CharField(max_length=45)
    kek_to_retrieve = models.ManyToManyField(KEK)

    objects = KeyMold()

    class Meta:
        verbose_name = 'DEK'

    def wrap_key(self, kek, password):
        if isinstance(kek, KEK) and isinstance(password, str):
            kek.unwrap_key(password)
            self.crypto.nonce = b64decode(kek.result_wrapped_nonce)
            # print(self.result_wrappedDek)
            self.dek = self.crypto.AesEncryptEAX(b64decode(self.result_wrappedDek), kek.kek)
            kek.wrap_key(password)
            return self.dek

        elif isinstance(kek, KEK) and isinstance(password, bytes):
            kek.unwrap_key(password)
            # if kek.kek == None:
            #    somekek = crypto.Sha256(bytes(password))
            #    somekek = crypto.AesEncryptEAX(password, somekek)
            #    p = KEK(result_wrapped_kek=b64encode(somekek),result_wrapped_nonce=crypto.nonce)
            #    t = p
            #    t.save()
            #    #print("password below: ")
            #    print(password)
            #    get_it = t.unwrap_key(password)
            #    self.crypto.nonce = b64decode(t.result_wrapped_nonce)
            #    #print("WrappedDek 1 below:")
            #    #print(self.result_wrappedDek.value_from_object())
            #    #print(kek.kek)
            #    self.dek = self.crypto.AesEncryptEAX(self.result_wrappedDek, self.crypto.Sha256(get_it))
            #    t.wrap_key(password)
            #    return self.dek

            # else:
            # kek.unwrap_key(password)
            self.crypto.nonce = b64decode(kek.result_wrapped_nonce)
            # print("WrappedDek 2 below:")
            # print(self.result_wrappedDek)
            self.dek = self.crypto.AesEncryptEAX(self.result_wrappedDek, kek.kek)
            kek.wrap_key(password)
            return self.dek

        else:
            try:
                # print("password below: ")
                # print(password)
                kek.unwrap_key(password)
                self.crypto.nonce = b64decode(kek.result_wrapped_nonce)
                # print("WrappedDek 3 below:")
                # print(self.result_wrappedDek.value_from_object())
                # print(kek.kek)
                self.dek = self.crypto.AesEncryptEAX(self.result_wrappedDek, self.crypto.Sha256(kek.kek))
                kek.wrap_key(password)
                return self.dek

            except:
                print('someone has attempted to spoof the DEK (data encryption key)')

    def unwrap_key(self, kek, password):
        if isinstance(kek, KEK) and isinstance(password, str):
            master = kek.unwrap_key(password.encode())

            self.crypto.nonce = b64decode(self.result_wrapped_nonce)
            self.dek = self.crypto.AesDecryptEAX(b64decode(self.result_wrappedDek), self.crypto.Sha256(master))
            # print("JUSTDECRYPTED")
            kek.wrap_key(password)
            return self.dek

        elif isinstance(kek, KEK) and isinstance(password, bytes):
            kek.unwrap_key(password)
            # print("KEK is: " + str(kek.kek))
            # if kek.kek == None:
            #    somekek = self.crypto.Sha256(bytes(password))
            #    somekek = self.crypto.AesEncryptEAX(password, somekek)
            #    p = KEK(result_wrapped_kek=b64encode(somekek),result_wrapped_nonce=self.crypto.nonce)
            #    p.save()
            #    #print("KEK at 173:")
            #    print("kek,object: " + str(p.kek))
            #    self.crypto.nonce = b64decode(self.result_wrapped_nonce)
            #    self.dek = self.crypto.AesDecryptEAX(b64decode(self.result_wrappedDek), self.crypto.Sha256(p.unwrap_key(password)))
            #    kek.wrap_key(password)
            #    return self.dek

            if isinstance(self.result_wrapped_nonce, str):
                print("NONCEDEK_STR:" + self.result_wrapped_nonce)
                result_wrapped_nonce = (self.result_wrapped_nonce.encode()).replace(b"b'", b'')
                result_wrapped_nonce = result_wrapped_nonce[:-1]
                result_wrapped_nonce = result_wrapped_nonce + b'=' * (len(result_wrapped_nonce) % 4)
                self.crypto.nonce = b64decode(result_wrapped_nonce)
                print(b'NONCEDEK>' + result_wrapped_nonce)

            elif isinstance(self.result_wrapped_nonce, bytes):
                print("YOLO")
                self.crypto.nonce = b64decode(self.result_wrapped_nonce)

            if (not isinstance(self.result_wrappedDek, bytes)):
                # print(len(self.result_wrappedDek.encode()))
                print("did we make it here" + str(self.result_wrappedDek))
                result_wrappedDek = (self.result_wrappedDek.encode()).replace(b"b'", b'')
                result_wrappedDek = result_wrappedDek[:-1]
                print("did we make it here" + str(result_wrappedDek))
                wrapper = result_wrappedDek + b'=' * (len(result_wrappedDek) % 4)
                print("wrapper" + str(wrapper))

            else:
                # print(len(self.result_wrappedDek))
                print(self.result_wrappedDek)
                result_wrappedDek = self.result_wrappedDek.replace(b"b'", b'')
                result_wrappedDek = result_wrappedDek
                wrapper = result_wrappedDek + b'=' * (len(result_wrappedDek) % 4)
                # wrapper = self.result_wrappedDek.value_from_object()

            cryptoObj = CryptoTools()
            print("line 246:")
            # print(kek.kek)
            print(wrapper)
            self.dek = self.crypto.AesDecryptEAX(b64decode(wrapper), cryptoObj.Sha256(kek.kek))
            # self.kek_to_retrieve.get_object().wrap_key(password)
            print("DEBUG>DEK>: ")
            print(self.dek)
            kek.wrap_key(password)

            return self.dek

        else:
            try:
                if not isinstance(password, bytes):
                    password = password.encode()
                else:
                    password = pasword

                kek.unwrap_key(password)
                self.crypto.nonce = b64decode(self.result_wrapped_nonce)
                # print("about to decrypt dek")
                self.dek = self.crypto.AesDecryptEAX(b64decode(self.result_wrappedDek), self.crypto.Sha256(kek.kek))
                print("DEBUG>DEK>: ")
                print(self.dek)
                kek.wrap_key(password)
                return self.dek
            except:
                print('someone has attempted to spoof the KEK2 (key encryption key)')


'''
function to DeriveKek_default from an arbitrary password
'''


def DeriveKek_default(password):
    crypto = CryptoTools()
    if len(crypto.Sha256(password.encode())) != LENGTH_OF_KEK:
        print('ERROR> NOT ENOUGH BYTES IN PASSWORD FOR DEK, NEED 32')
    if isinstance(password, str):
        somekek = crypto.Sha256(bytes(password.encode()))
        somekek = crypto.AesEncryptEAX(password.encode(), somekek)
        k = KEK(result_wrapped_kek=b64encode(somekek))
        k.save()
        return k

    elif isinstance(password, bytes):
        somekek = crypto.Sha256(bytes(password.encode()))
        somekek = crypto.AesEncryptEAX(password.encode(), somekek)
        k = KEK(result_wrapped_kek=b64encode(somekek), result_wrapped_nonce=crypto.nonce)
        k.save()
        return k

    else:
        print("ERROR>UNABLE TO GENERATE WRAPPED KEK, USE A CORRECT KEY FORMAT FOR WRAPPING")


'''
NeutronCore is a models.Model type class that allow for KEKs to be generated through a kek generator, time_generated, and of course the kek object
this is the model for when you need access to multiple KEKS for a single user

USE CASE: is old data relies on older KEKs but that older KEK is still active
but the user happened to change their password which would entail creating a new password and from that time the DEK chain would change to the newly
created KEK wrapped using the newly changed password.
'''


class NeutronCore(models.Model):
    kek = models.ForeignKey(
        get_user_model(), related_name='KEK',
        on_delete=models.CASCADE,
        default=1)

    kekgenerator = models.ManyToManyField(KEK, related_name='KEK')

    time_generated = models.DateTimeField('date star collapsed', auto_now_add=True)

    objects = KeyMold()

    class Meta:
        verbose_name = 'neutron core'
        ordering = ['-time_generated']
        get_latest_by = 'time_generated'

    def DeriveKek(self, password):
        crypto = CryptoTools()
        if len(crypto.Sha256(password.encode())) != LENGTH_OF_KEK:
            print('ERROR> NOT ENOUGH BYTES IN PASSWORD FOR DEK, NEED 32')
        if isinstance(password, str):
            somekek = crypto.Sha256(bytes(password.encode()))
            somekek = crypto.AesEncryptEAX(password.encode(), somekek)
            k = KEK(result_wrapped_kek=b64encode(somekek), result_wrapped_nonce=b64encode(crypto.nonce))
            k.save()
            return k

        elif isinstance(password, bytes):
            somekek = crypto.Sha256(bytes(password.encode()))
            somekek = crypto.AesEncryptEAX(password.encode(), somekek)
            k = KEK(result_wrapped_kek=b64encode(somekek), result_wrapped_nonce=b64encode(crypto.nonce))
            k.save()
            return k

        else:
            print("ERROR>UNABLE TO GENERATE WRAPPED KEK, USE A CORRECT KEY FORMAT FOR WRAPPING")


def DeriveDek_default(password):
    crypto = CryptoTools()
    # if isinstance(NeutronMatterCollector.kekForDek, KEK):
    #    if password != None and isinstance(password, str):
    #        #Generate DEK based off this formula sha256(256 bit SALT + KEK)
    #        self.SALT = crypto.RandomNumber(32)
    #        crypto.nonce = b64decode(NeutronMatterCollector.kekForDek.result_wrapped_nonce)
    #        DerivedDek = crypto.Sha256(bytes(self.kekForDek.result_SALT) + crypto.AesDecryptEAX(b64decode(str(self.kekForDek.result_wrapped_kek)),crypto.Sha256(bytes(password.encode()))))
    #        self.dekgenerator = DerivedDek
    #        dek = DerivedDek
    #        dek = DEK.wrap_key(kek, password)
    #        newDek = DEK(result_wrappedDek=b64encode(dek), result_SALT=b64encode(NeutronMatterCollector.kekForDek_SALT), kek_to_retrieve=NeutronMatterCollector.kekForDek, result_wrapped_nonce=b64encode(crypto.nonce))
    #        newDek.save()
    #        return newDek

    # else:
    print("made it to DevideDek_default")
    kekForDek = NeutronCore(get_user_model()).DeriveKek(password)
    if isinstance(kekForDek, KEK):
        if password != None and isinstance(password, str):
            # Generate DEK based off this formula sha256(256 bit SALT + KEK)
            self.SALT = crypto.RandomNumber(32)
            # print(self.kekForDek.result_wrapped_kek)
            # print(password.encode())
            crypto.nonce = b64decode(kekForDek.result_wrapped_nonce)
            DerivedDek = crypto.Sha256(bytes(kekForDek.result_SALT) + crypto.AesDecryptEAX(
                bytes(b64decode(str(kekForDek.result_wrapped_kek).encode())),
                crypto.Sha256(bytes(password.encode()))))
            dekgenerator = DerivedDek
            dek = DerivedDek
            dek = DEK.wrap_key(dek, password)
            newDek = DEK(result_wrappedDek=b64encode(dek), result_SALT=kekForDek.result_SALT,
                         kek_to_retrieve=kekForDek, result_wrapped_nonce=b64encode(crypto.nonce))
            newDek.save()
            return newDek


'''
NeutronMatterCollector is for generating a Data Encryption Key [DEK]
no inputs
'''


class NeutronMatterCollector(models.Model):
    dekgenerator = models.ManyToManyField(DEK,
                                          related_name='kek_for_dek_generator')  # length of 32 bytes (256bits) in base64 is 44, but will need to include an = ending and null so extending to 45.
    # secureNote = models.ForeignKey('SecureDataAtRestPost', related_name='secureNote', on_delete=models.CASCADE)
    try:
        # print(get_user_model().user)
        kekForDek = models.ForeignKey(
            KEK, related_name='KEK_obj',
            on_delete=models.CASCADE, default=1)
        dek = models.ForeignKey(
            DEK, related_name='DEK_obj',
            on_delete=models.CASCADE,
            default=1)
    except:
        try:
            print("unable to locate KEK for username creating new one, this could be due to a new user")
            kekForDek = models.ForeignKey(KEK, related_name='KEK_obj',
                                          on_delete=models.CASCADE, default=1)
            dek = models.ForeignKey(DEK, related_name='DEK_obj', on_delete=models.CASCADE, default=1)
            print("successfully made a KEK and DEK")

        except:
            print("unable to create KEK")
            print(get_user_model().natural_key(get_user_model()))

    time_generated = models.DateTimeField('date integrated', auto_now_add=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    objects = QuasiPlasma()

    class Meta:
        verbose_name = 'neutron matter collector'
        ordering = ['-time_generated']
        get_latest_by = 'time_generated'

    def DeriveDek(self, password):
        crypto = CryptoTools()
        if isinstance(NeutronMatterCollector.kekForDek, KEK):
            if password != None and isinstance(password, str):
                # Generate DEK based off this formula sha256(256 bit SALT + KEK)
                self.SALT = crypto.RandomNumber(32)
                crypto.nonce = b64decode(NeutronMatterCollector.kekForDek.result_wrapped_nonce)
                DerivedDek = crypto.Sha256(bytes(self.SALT) + crypto.AesDecryptEAX(
                    bytes(b64decode(str(self.kekForDek.result_wrapped_kek).encode())),
                    crypto.Sha256(bytes(password.encode()))))
                self.dekgenerator = DerivedDek
                dek = DerivedDek
                dek = DEK.wrap_key(dek, password)
                newDek = DEK(result_wrappedDek=b64encode(dek), result_SALT=b64encode(self.SALT),
                             kek_to_retrieve=self.dekgenerator)
                newDek.save()
                return newDek

        else:
            self.kekForDek = NeutronCore(get_user_model()).DeriveKek(password)
            if isinstance(self.kekForDek, KEK):
                if password != None and isinstance(password, str):
                    # Generate DEK based off this formula sha256(256 bit SALT + KEK)
                    self.SALT = crypto.RandomNumber(32)
                    crypto.nonce = b64decode(self.kekForDek.result_wrapped_nonce)
                    # print(self.kekForDek.result_wrapped_nonce)
                    # print(self.kekForDek.result_wrapped_kek)
                    # print(password)
                    DerivedDek = crypto.Sha256(
                        bytes(self.SALT) + crypto.AesDecryptEAX(b64decode(self.kekForDek.result_wrapped_kek),
                                                                crypto.Sha256(bytes(password.encode()))))
                    # self.dekgenerator.id.set(self.request.user)

                    dek = DerivedDek
                    # newkey = DEK()
                    # newkey.dek = dek
                    # dek = DEK.wrap_key(newkey, kek=self.kekForDek, password=password.encode())
                    dek = crypto.AesEncryptEAX(dek, crypto.Sha256(
                        crypto.AesDecryptEAX(b64decode(self.kekForDek.result_wrapped_kek),
                                             crypto.Sha256(bytes(password.encode())))))
                    newDek = DEK(result_wrappedDek=b64encode(dek), result_SALT=b64encode(self.SALT),
                                 result_wrapped_nonce=b64encode(crypto.nonce), id=self.id)
                    # newDek.kek_to_retrieve.set(self.dekgenerator)
                    # self.time_generated = models.DateTimeField('date integrated', auto_now_add=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                    self.save()
                    newDek.save()
                    self.dekgenerator.add(newDek)
                    self.save()
                    return newDek


class KryptonianSpeak:

    def db_for_read(self, model, **hints):
        return 'default'

    def db_for_write(self, model, **hints):
        return 'default'

    def allow_relation(self, obj1, obj2, **hints):
        return True
        '''
        db_list = ('default', 'superHeros', 'icePick', 'neutronStarMatter', 'neutronStarMold')
        if obj1._state.db in db_list and obj2._state.db in db_list:
            return True
        return None
        '''

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        return True
