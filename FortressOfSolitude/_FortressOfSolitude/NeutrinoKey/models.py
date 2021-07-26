"""
DBA copyright May 2021 by 1337_TECH
Austin, Texas
All Rights Reserved, No Warranties implied or expressed.
https://github.com/BDD16/PythonMisc..git
"""

# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models

from datetime import datetime
from .cryptoutils import CryptoTools
from base64 import b64encode, b64decode
from django.contrib.auth import get_user_model
from typing import Union

# Create your models here.

# Constants
LENGTH_OF_KEK = 32  # 256 bits or 32 bytes
LENGTH_OF_DEK = 32  # 256 bits or 32 bytes
LENGTH_OF_SALT = 32  # 256 bits or 32 bytes


class KeyMold(models.Manager):
    """
    KeyMold is a models.Manager clas extension that includes creating a Kek and retrieving a kek
    no inputs
    """

    def _create_kek(self, request, **kwargs):
        pwd = request.user.password
        self.kek = DeriveKek_default(pwd)
        return self.kek

    def get_queryset(self):
        qs = models.QuerySet(self.model)
        if self._db is not None:
            qs = qs.using('neutronstarmatter')
        return qs


class TelescopeCoord(models.Manager):
    """
    TelescopeCoord is a models.Manager that allows to find the neutron star that will be used for the keyMold to make a Key Encryption Key [kek].
    no inputs
    """

    def get_queryset(self):
        qs = models.QuerySet(self.model)
        if self._db is not None:
            qs = qs.using('neutronstar_telecope')
        return qs


class QuasiPlasma(models.Manager):
    """
    QuasiPlasma is a models.Manager that allows for deriving Data Encryption Keys [DEKs] and retrieving deks from the neutron stars plasma.
    no inputs
    """

    def _create_dek(self, request, **kwargs):
        pwd = request.user.password
        self.dek = DeriveDek_default(pwd)
        return self.dek

    def get_queryset(self):
        qs = models.QuerySet(self.model)
        if self._db is not None:
            qs = qs.using('MoltenNeutron')
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
        if isinstance(password, str) and self.kek is None and self.wrappedKek is None:
            self.crypto.nonce = b64decode(self.result_wrapped_nonce)
            self.kek = self.crypto.AesDecryptEAX(b64decode(self.result_wrapped_kek),
                                                 self.crypto.Sha256(password.encode()))
        if isinstance(password, bytes) and self.kek is None and self.wrappedKek is None:
            if isinstance(self.result_wrapped_nonce, str):
                result_wrapped_nonce = (self.result_wrapped_nonce.encode()).replace(b"b'", b'')
                result_wrapped_nonce = result_wrapped_nonce[:-1]
                result_wrapped_nonce = result_wrapped_nonce + b'=' * (len(self.result_wrapped_nonce) % 4)
                self.crypto.nonce = b64decode(result_wrapped_nonce)
            else:
                self.crypto.nonce = b64decode(self.result_wrapped_nonce)
            if isinstance(self.result_wrapped_kek, str):
                result_wrapped_kek = (self.result_wrapped_kek.encode()).replace(b"b'", b'')

                result_wrapped_kek = result_wrapped_kek[:-1]
                result_wrapped_kek = result_wrapped_kek + b'=' * (len(result_wrapped_kek) % 4)
            elif isinstance(self.result_wrapped_kek, bytes):
                result_wrapped_kek = self.result_wrapped_kek
            self.kek = self.crypto.AesDecryptEAX(b64decode(result_wrapped_kek), CryptoTools().Sha256(password))
            # TODO: Come up with a SecureErase of objects and classes to wipe out of memory decryption artifacts
            del result_wrapped_kek
            del self.result_wrapped_kek

        else:
            try:
                self.crypto.nonce = b64decode(self.result_wrapped_nonce)
                if not isinstance(password, bytes):
                    password = password.encode()
                self.kek = self.crypto.AesDecryptEAX(b64decode(self.result_wrapped_kek), self.crypto.Sha256(password))
                del self.wrappedKek
            except Exception as e:
                print(f'someone has attempted to spoof the KEK (key encryption key): {e}')

        return self.kek

    def wrapKey(self, password: Union[str, bytes], data: bytes) -> bytes:
        if isinstance(password, str) and self.kek is None:
            self.kek = self.crypto.AesEncryptEAX(data, self.crypto.Sha256(password.encode()))
            self.wrappedKek = self.kek
            self.kek = None

        elif isinstance(password, bytes) and self.kek == None:
            self.kek = self.crypto.AesEncryptEAX(data, self.crypto.Sha256(password))
            self.wrappedKek = b64encode(self.kek)
            self.kek = None
        elif self.kek is not None:
            try:
                self.crypto.nonce = b64decode(self.result_wrapped_nonce)
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


class DEK(models.Model):
    """
    using the model of KEK unwrap and wrap the kek then unwrap the dek then pass the dek to a more useable object
    perhaps this will also fetch the dek that is associated with that data model, so needs to be a manytomany relation.

    DEK is a models.Model or Data Encryption Key class that allows to store, derive, and wrap Data Encryption Keys from a KEK and Salt
    """
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

    def wrapKey(self, kek: KEK, password: Union[str, bytes]) -> bytes:
        if isinstance(kek, KEK) and isinstance(password, str):
            kek.unwrap_key(password)
            self.crypto.nonce = b64decode(kek.result_wrapped_nonce)
            self.dek = self.crypto.AesEncryptEAX(b64decode(self.result_wrappedDek), kek.kek)
            kek.wrapKey(password)
            return self.dek

        elif isinstance(kek, KEK) and isinstance(password, bytes):
            kek.unwrap_key(password)

            self.crypto.nonce = b64decode(kek.result_wrapped_nonce)
            self.dek = self.crypto.AesEncryptEAX(self.result_wrappedDek, kek.kek)
            kek.wrapKey(password)
            return self.dek

        else:
            try:
                kek.unwrap_key(password)
                self.crypto.nonce = b64decode(kek.result_wrapped_nonce)
                self.dek = self.crypto.AesEncryptEAX(self.result_wrappedDek, self.crypto.Sha256(kek.kek))
                kek.wrapKey(password)
                return self.dek

            except:
                print('someone has attempted to spoof the DEK (data encryption key)')

    def unwrapKey(self, kek: KEK, password) -> bytes:
        if isinstance(kek, KEK) and isinstance(password, str):
            master = kek.unwrap_key(password.encode())

            self.crypto.nonce = b64decode(self.result_wrapped_nonce)
            self.dek = self.crypto.AesDecryptEAX(b64decode(self.result_wrappedDek), self.crypto.Sha256(master))
            kek.wrapKey(password)
            return self.dek

        elif isinstance(kek, KEK) and isinstance(password, bytes):
            kek.unwrap_key(password)

            if isinstance(self.result_wrapped_nonce, str):
                result_wrapped_nonce = (self.result_wrapped_nonce.encode()).replace(b"b'", b'')
                result_wrapped_nonce = result_wrapped_nonce[:-1]
                result_wrapped_nonce = result_wrapped_nonce + b'=' * (len(result_wrapped_nonce) % 4)
                self.crypto.nonce = b64decode(result_wrapped_nonce)

            elif isinstance(self.result_wrapped_nonce, bytes):
                self.crypto.nonce = b64decode(self.result_wrapped_nonce)

            if not isinstance(self.result_wrappedDek, bytes):
                result_wrappedDek = (self.result_wrappedDek.encode()).replace(b"b'", b'')
                result_wrappedDek = result_wrappedDek[:-1]
                wrapper = result_wrappedDek + b'=' * (len(result_wrappedDek) % 4)

            else:
                result_wrappedDek = self.result_wrappedDek.replace(b"b'", b'')
                result_wrappedDek = result_wrappedDek
                wrapper = result_wrappedDek + b'=' * (len(result_wrappedDek) % 4)

            cryptoObj = CryptoTools()
            self.dek = self.crypto.AesDecryptEAX(b64decode(wrapper), cryptoObj.Sha256(kek.kek))
            kek.wrapKey(password)

            return self.dek

        else:
            try:
                if not isinstance(password, bytes):
                    password = password.encode()
                else:
                    password = password

                kek.unwrap_key(password)
                self.crypto.nonce = b64decode(self.result_wrapped_nonce)
                self.dek = self.crypto.AesDecryptEAX(b64decode(self.result_wrappedDek), self.crypto.Sha256(kek.kek))
                kek.wrapKey(password)
                return self.dek
            except:
                print('someone has attempted to spoof the KEK2 (key encryption key)')


def DeriveKek_default(password: Union[str, bytes]) -> KEK:
    """
    function to DeriveKek_default from an arbitrary password
    """
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


class NeutronCore(models.Model):
    """
    NeutronCore is a models.Model type class that allow for KEKs to be generated through a kek generator, time_generated, and of course the kek object
    this is the model for when you need access to multiple KEKS for a single user

    USE CASE: is old data relies on older KEKs but that older KEK is still active
    but the user happened to change their password which would entail creating a new password and from that time the DEK chain would change to the newly
    created KEK wrapped using the newly changed password.
    """
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

    def DeriveKek(self, password: Union[str, bytes]) -> KEK:
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


def DeriveDek_default(password: Union[str, bytes]) -> DEK:
    crypto = CryptoTools()
    self.kekForDek = NeutronCore(get_user_model()).DeriveKek(password)
    if isinstance(self.kekForDek, KEK):
        if password != None and isinstance(password, str):
            self.SALT = crypto.RandomNumber(32)
            crypto.nonce = b64decode(self.kekForDek.result_wrapped_nonce)
            DerivedDek = crypto.Sha256(bytes(self.kekForDek.result_SALT) + crypto.AesDecryptEAX(
                bytes(b64decode(str(self.kekForDek.result_wrapped_kek).encode())),
                crypto.Sha256(bytes(password.encode()))))
            self.dekgenerator = DerivedDek
            dek = DerivedDek
            dek = DEK.wrapKey(kek, password)
            newDek = DEK(result_wrappedDek=b64encode(dek), result_SALT=self.kekFroDek.result_SALT,
                         kek_to_retrieve=self.kekForDek, result_wrapped_nonce=b64encode(crypto.nonce))
            newDek.save()
            return newDek


class NeutronMatterCollector(models.Model):
    """
    NeutronMatterCollector is for generating a Data Encryption Key [DEK]
    no inputs
    """
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

    def DeriveDek(self, password: Union[str, bytes]) -> DEK:
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
                dek = DEK.wrapKey(kek, password)
                newDek = DEK(result_wrappedDek=b64encode(dek), result_SALT=b64encode(self.SALT),
                             kek_to_retrieve=self.dekgenerator)
                newDek.save()
                return newDek

        else:
            self.kekForDek = NeutronCore(get_user_model()).DeriveKek(password)
            if isinstance(self.kekForDek, KEK):
                if password is not None and isinstance(password, str):
                    # Generate DEK based off this formula sha256(256 bit SALT + KEK)
                    self.SALT = crypto.RandomNumber(32)
                    crypto.nonce = b64decode(self.kekForDek.result_wrapped_nonce)
                    DerivedDek = crypto.Sha256(
                        bytes(self.SALT) + crypto.AesDecryptEAX(b64decode(self.kekForDek.result_wrapped_kek),
                                                                crypto.Sha256(bytes(password.encode()))))

                    dek = DerivedDek
                    dek = crypto.AesEncryptEAX(dek, crypto.Sha256(
                        crypto.AesDecryptEAX(b64decode(self.kekForDek.result_wrapped_kek),
                                             crypto.Sha256(bytes(password.encode())))))
                    newDek = DEK(result_wrappedDek=b64encode(dek), result_SALT=b64encode(self.SALT),
                                 result_wrapped_nonce=b64encode(crypto.nonce), id=self.id)
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
