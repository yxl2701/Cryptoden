"""
核心功能测试模块
=================
测试加密、解密、递归解密和AI分析等核心功能
"""

import unittest
import sys
from pathlib import Path

# 添加项目根目录到Python路径
sys.path.append(str(Path(__file__).parent.parent))

from core.crypto_loader import CryptoLoader
from utils.recursive_decryptor import AsyncRecursiveDecryptor
from utils.ai_assistant import AIConfig, AIClient
from algorithms.encoding import base58, base62
from algorithms.encoding import base32, base64, base85, base91, hex as hex_codec
from algorithms.encoding import (
    ascii85,
    base16,
    base64_nopad,
    base64_urlsafe,
    cp1252_hex,
    gbk_hex,
    html_entity_decimal,
    html_entity_hex,
    idna,
    punycode,
    raw_unicode_escape_codec,
    unicode_escape_codec,
    utf16le,
    utf32be,
    utf8_binary,
    utf8_decimal,
    utf8_decimal_comma,
    utf8_hex_lower,
    utf8_octal,
    utf9,
)
from algorithms.hash import md5, sha1, sha256, sha512
from algorithms.hash import (
    adler32,
    blake2b,
    blake2s,
    crc32,
    hmac_sha256,
    sha224,
    sha384,
    sha3_256,
    sha3_512,
    shake128,
)
from algorithms.other import even_odd_transpose, pair_swap, reverse_text, swapcase_text
from algorithms.asymmetric.ecc import ecc as ecc_module
from algorithms.asymmetric.ecc import ecc_sign
from algorithms.asymmetric.ecc.attacks import (
    ecc_nonce_reuse_attack,
    ecc_point_order_attack,
    ecc_public_key_analysis_attack,
    ecc_small_curve_enumeration_attack,
    ecc_small_curve_dlp_attack,
    ecdsa_known_nonce_attack,
    ecdsa_nonce_affine_attack,
    ecdsa_nonce_difference_attack,
    ecdsa_nonce_ratio_attack,
)
from algorithms.asymmetric.rsa import rsa as rsa_module
from algorithms.asymmetric.rsa.utils import parse_input_value
from algorithms.asymmetric.rsa.attacks import common_modulus_attack, known_factor_attack
from de_recursion import recursive_decrypt


class TestCoreFunctions(unittest.TestCase):
    """测试核心功能"""
    
    def setUp(self):
        """设置测试环境"""
        self.base_path = Path(__file__).parent.parent
        self.crypto_loader = CryptoLoader(self.base_path)
        self.crypto_loader.load_all_modules()
    
    def test_encryption_decryption(self):
        """测试加密和解密功能"""
        # 测试凯撒密码
        plaintext = "hello world"
        encrypted = self.crypto_loader.execute_encrypt('caesar凯撒密码', plaintext, shift=3)
        self.assertIsNotNone(encrypted)
        self.assertNotEqual(encrypted, plaintext)
        
        decrypted = self.crypto_loader.execute_decrypt('caesar凯撒密码', encrypted, shift=3)
        self.assertIsNotNone(decrypted)
        self.assertEqual(decrypted, plaintext)
        
        # 测试Base64编码解码
        encoded = self.crypto_loader.execute_encrypt('Base64', plaintext)
        self.assertIsNotNone(encoded)
        
        decoded = self.crypto_loader.execute_decrypt('Base64', encoded)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded, plaintext)
    
    def test_one_click_decrypt(self):
        """测试一键解密功能"""
        # 测试Base64编码的文本
        test_text = "aGVsbG8gd29ybGQ="  # Base64编码的 "hello world"
        results = self.crypto_loader.try_decrypt_all(test_text)
        
        # 检查是否有成功的解密结果
        success_results = [r for r in results if r['success']]
        self.assertGreater(len(success_results), 0)

    def test_one_click_decrypt_uses_bruteforce_and_sorts_matches(self):
        """测试一键解密支持 decrypt_all，并将关键词结果置前"""
        results = self.crypto_loader.try_decrypt_all('khoor zruog', match_patterns=['hello'])
        self.assertGreater(len(results), 0)
        caesar_results = [r for r in results if r['name'] == 'caesar凯撒密码' and r['is_brute']]
        self.assertTrue(caesar_results)
        self.assertIn('hello world', str(caesar_results[0]['result']))
        self.assertEqual(caesar_results[0]['params'], 'shift=3')
        self.assertLess(
            results.index(caesar_results[0]),
            len(results) // 2,
        )

    def test_one_click_decrypt_expands_small_keyspace_results(self):
        """测试一键解密会逐条展开小密钥空间爆破结果"""
        results = self.crypto_loader.try_decrypt_all('khoor zruog', match_patterns=['hello'])
        caesar_results = [r for r in results if r['name'] == 'caesar凯撒密码' and r['is_brute']]

        self.assertGreaterEqual(len(caesar_results), 25)
        self.assertEqual(caesar_results[0]['result'], 'hello world')
        self.assertEqual(caesar_results[0]['params'], 'shift=3')

    def test_base_n_roundtrip_and_invalid_input(self):
        """测试Base58/Base62共享编码逻辑"""
        samples = ['', 'hello world', '\x00hello']

        for module in (base58, base62):
            for sample in samples:
                encoded = module.encrypt(sample)
                decoded = module.decrypt(encoded)
                self.assertEqual(decoded, sample)

        self.assertTrue(base58.decrypt('0').startswith('解码错误:'))
        self.assertTrue(base62.decrypt('!').startswith('解码错误:'))

    def test_classical_substitution_roundtrip(self):
        """测试古典替换密码的共享路径"""
        plaintext = "Hello, World! 123"

        caesar_encrypted = self.crypto_loader.execute_encrypt('caesar凯撒密码', plaintext, shift='29')
        self.assertEqual(caesar_encrypted, 'Khoor, Zruog! 123')
        caesar_decrypted = self.crypto_loader.execute_decrypt('caesar凯撒密码', caesar_encrypted, shift='29')
        self.assertEqual(caesar_decrypted, plaintext)

        atbash_encrypted = self.crypto_loader.execute_encrypt('atbash埃特巴什码', plaintext)
        self.assertEqual(atbash_encrypted, 'Svool, Dliow! 123')
        atbash_decrypted = self.crypto_loader.execute_decrypt('atbash埃特巴什码', atbash_encrypted)
        self.assertEqual(atbash_decrypted, plaintext)

    def test_rot_family_roundtrip(self):
        """测试ROT系列只转换目标ASCII字符"""
        samples = {
            'rot5': ('Phone 12345, 中文', 'Phone 67890, 中文'),
            'rot13': ('Hello 123, 中文', 'Uryyb 123, 中文'),
            'rot18': ('Hello 123, 中文', 'Uryyb 678, 中文'),
            'rot47': ('Hello!', 'w6==@P'),
        }

        for algo_name, (plaintext, expected) in samples.items():
            encrypted = self.crypto_loader.execute_encrypt(algo_name, plaintext)
            self.assertEqual(encrypted, expected)
            decrypted = self.crypto_loader.execute_decrypt(algo_name, encrypted)
            self.assertEqual(decrypted, plaintext)

    def test_common_encoding_cleanup_and_errors(self):
        """测试常用编码算法的输入清理和非法字符处理"""
        self.assertEqual(base64.decrypt('aGVs bG8'), 'hello')
        self.assertEqual(base64.decrypt('aGVsbG8'), 'hello')
        self.assertTrue(base64.decrypt('aGVsbG8!').startswith('解码错误:'))

        self.assertEqual(base32.decrypt('nbswy3dp'), 'hello')
        self.assertEqual(base32.decrypt('NBSW Y3DP'), 'hello')
        self.assertTrue(base32.decrypt('NBSWY3D!').startswith('解码错误:'))

        self.assertEqual(hex_codec.decrypt('0x68656C6C6F'), 'hello')
        self.assertEqual(hex_codec.decrypt('68:65-6C 6C\n6F'), 'hello')
        self.assertTrue(hex_codec.decrypt('686').startswith('解码错误:'))

        self.assertEqual(base85.decrypt('BOu!rDZ'), 'hello')
        self.assertTrue(base85.decrypt('BOu!r\x7f').startswith('解码错误:'))
        self.assertTrue(base91.decrypt('>OwJh>Io0\x7f').startswith('解码错误:'))

    def test_new_encoding_algorithms_roundtrip(self):
        """测试新增编码算法的基本可逆性"""
        unicode_sample = '你好, Cryptoden!'
        ascii_sample = 'hello.example'
        byte_sample = 'Hello 你好'
        ascii_only_sample = 'Hello-123'

        unicode_modules = [
            base16,
            ascii85,
            base64_urlsafe,
            base64_nopad,
            unicode_escape_codec,
            raw_unicode_escape_codec,
            html_entity_decimal,
            html_entity_hex,
            utf9,
            utf16le,
            utf32be,
            gbk_hex,
            utf8_binary,
            utf8_octal,
            utf8_decimal,
            utf8_decimal_comma,
            utf8_hex_lower,
        ]
        for module in unicode_modules:
            encoded = module.encrypt(unicode_sample if module is not utf8_hex_lower else byte_sample)
            decoded = module.decrypt(encoded)
            expected = byte_sample if module is utf8_hex_lower else unicode_sample
            self.assertEqual(decoded, expected)

        ascii_modules = [cp1252_hex, punycode, even_odd_transpose, pair_swap, reverse_text, swapcase_text]
        for module in ascii_modules:
            encoded = module.encrypt(ascii_only_sample)
            decoded = module.decrypt(encoded)
            self.assertEqual(decoded, ascii_only_sample)

        idna_encoded = idna.encrypt('你好.example')
        self.assertEqual(idna.decrypt(idna_encoded), '你好.example')

    def test_algorithm_count_reaches_target(self):
        """测试算法数量达到至少 100 个加密模块"""
        self.assertGreaterEqual(len(self.crypto_loader.encrypt_modules), 115)

    def test_hash_outputs(self):
        """测试哈希模块共享实现的输出稳定性"""
        self.assertEqual(md5.encrypt('hello'), '5d41402abc4b2a76b9719d911017c592')
        self.assertEqual(sha1.encrypt('hello'), 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d')
        self.assertEqual(sha256.encrypt('hello'), '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824')
        self.assertTrue(sha512.encrypt('hello').startswith('9b71d224bd62f3785d96d46ad3ea3d733'))
        self.assertEqual(sha224.encrypt('hello'), 'ea09ae9cc6768c50fcee903ed054556e5bfc8347907f12598aa24193')
        self.assertEqual(sha384.encrypt('hello'), '59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcdb9c666fa90125a3c79f90397bdf5f6a13de828684f')
        self.assertEqual(sha3_256.encrypt('hello'), '3338be694f50c5f338814986cdf0686453a888b84f424d792af4b9202398f392')
        self.assertTrue(sha3_512.encrypt('hello').startswith('75d527c368f2efe848ecf6b073a36767'))
        self.assertTrue(blake2b.encrypt('hello').startswith('e4cfa39a3d37be31c59609e807970799'))
        self.assertEqual(blake2s.encrypt('hello'), '19213bacc58dee6dbde3ceb9a47cbb330b3d86f8cca8997eb00be456f140ca25')
        self.assertEqual(shake128.encrypt('hello', length=8), '8eb4b6a932f28033')
        self.assertEqual(hmac_sha256.encrypt('hello', key='secret'), '88aab3ede8d3adf94d26ab90d3bafd4a2083070c3bcce9c014ee04a443847c0b')
        self.assertEqual(crc32.encrypt('hello'), '3610a686')
        self.assertEqual(adler32.encrypt('hello'), '062c0215')

        all_hashes = self.crypto_loader.execute_encrypt('hash_all批量哈希', 'hello')
        self.assertIn('MD5:', all_hashes)
        self.assertIn('5d41402abc4b2a76b9719d911017c592', all_hashes)
        self.assertIn('SHA-256:', all_hashes)
        self.assertIn('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824', all_hashes)
        self.assertIn('SHA3-256:', all_hashes)

    def test_ecc_ecdsa_sign_verify(self):
        """测试 ECC ECDSA 签名和验签"""
        message = 'hello ecc signature'
        key_pair = ecc_module.generate_key_pair('P-256')
        self.assertIn('[私钥]', key_pair)
        private_key = key_pair.split('[私钥]', 1)[1].strip()
        public_key = key_pair.split('[公钥]', 1)[1].split('[私钥]', 1)[0].strip()

        signed = ecc_module.sign(message, private_key=private_key)
        self.assertIn('[签名]', signed)
        self.assertEqual(ecc_module.verify(message, signed, public_key=public_key), '验签成功')
        self.assertTrue(ecc_module.verify(message + '!', signed, public_key=public_key).startswith('验签失败:'))

        signed_via_algo = ecc_sign.encrypt(message, private_key=private_key)
        self.assertEqual(ecc_sign.decrypt(signed_via_algo, message=message, public_key=public_key), '验签成功')

    def test_ecc_attack_helpers(self):
        """测试ECC攻击辅助功能"""
        key_pair = ecc_module.generate_key_pair('P-256')
        public_key = key_pair.split('[公钥]', 1)[1].split('[私钥]', 1)[0].strip()
        analysis = ecc_public_key_analysis_attack.attack(public_key)
        self.assertTrue(analysis['success'])
        self.assertIn('曲线:', analysis['text'])

        attack = ecc_nonce_reuse_attack.attack(
            n='19',
            r='5',
            s1='3',
            s2='1',
            z1='7',
            z2='2',
        )
        self.assertTrue(attack['success'])
        self.assertIn('私钥 d =', attack['text'])

    def test_ecc_additional_attacks(self):
        """测试新增ECC攻击模块"""
        known_nonce = ecdsa_known_nonce_attack.attack(
            n='19',
            r='5',
            s='3',
            z='7',
            k='4',
        )
        self.assertTrue(known_nonce['success'])
        self.assertEqual(known_nonce['d'], 1)

        point_order = ecc_point_order_attack.attack(
            p='97',
            a='2',
            b='3',
            x='3',
            y='6',
        )
        self.assertTrue(point_order['success'])
        self.assertEqual(point_order['order'], 5)

        dlp = ecc_small_curve_dlp_attack.attack(
            p='97',
            a='2',
            b='3',
            gx='3',
            gy='6',
            qx='80',
            qy='10',
            use_sage='false',
        )
        self.assertTrue(dlp['success'])
        self.assertEqual(dlp['d'], 2)

        diff = ecdsa_nonce_difference_attack.attack(
            n='19',
            s1='3',
            z1='7',
            s2='1',
            z2='0',
            delta='1',
            r='5',
        )
        self.assertTrue(diff['success'])
        self.assertEqual(diff['d'], 1)

        ratio = ecdsa_nonce_ratio_attack.attack(
            n='19',
            s1='3',
            z1='10',
            s2='1',
            z2='5',
            alpha='2',
            r='5',
        )
        self.assertTrue(ratio['success'])
        self.assertEqual(ratio['d'], 1)

        affine = ecdsa_nonce_affine_attack.attack(
            n='19',
            s1='3',
            z1='17',
            s2='1',
            z2='17',
            alpha='2',
            beta='1',
            r='5',
        )
        self.assertTrue(affine['success'])
        self.assertEqual(affine['k1'], 1)
        self.assertEqual(affine['k2'], 3)
        self.assertEqual(affine['d'], 1)

        enum_result = ecc_small_curve_enumeration_attack.attack(p='97', a='2', b='3', use_sage='false')
        self.assertTrue(enum_result['success'])
        self.assertEqual(enum_result['order'], 100)

    def test_rsa_oaep_combined_output_roundtrip(self):
        """测试RSA输出中携带私钥时可直接解密"""
        encrypted = rsa_module.encrypt('hello', key_size='1024')
        self.assertIn('[公钥]', encrypted)
        self.assertIn('[私钥]', encrypted)
        self.assertEqual(rsa_module.decrypt(encrypted), 'hello')

    def test_rsa_value_parser(self):
        """测试RSA数值解析容错"""
        self.assertEqual(parse_input_value('0xff'), 255)
        self.assertEqual(parse_input_value(' AQAB '), 65537)
        self.assertIsNone(parse_input_value('not-valid-base64!'))

    def test_rsa_derive_parameters_from_primes(self):
        """测试RSA参数快算支持p/q/e/c推导明文"""
        p, q, e, m = 61, 53, 17, 65
        n = p * q
        c = pow(m, e, n)

        result = rsa_module.derive_parameters(p=p, q=q, e=e, c=c)

        self.assertTrue(result['success'])
        self.assertEqual(result['n'], 3233)
        self.assertEqual(result['phi'], 3120)
        self.assertEqual(result['d'], 2753)
        self.assertEqual(result['m'], m)
        self.assertEqual(result['m_crt'], m)
        self.assertIn('m = c^d mod n', result['text'])

    def test_rsa_derive_parameters_recovers_missing_factor(self):
        """测试RSA参数快算支持已知n和p推导q"""
        result = rsa_module.derive_parameters(n=3233, p=61, e=17)

        self.assertTrue(result['success'])
        self.assertEqual(result['q'], 53)
        self.assertEqual(result['d'], 2753)
 
    def test_rsa_attacks_accept_flexible_numbers(self):
        """测试常用RSA攻击支持十六进制/Base64数值输入"""
        known = known_factor_attack.attack('0xca1', '0x3d', 'AQAB')
        self.assertTrue(known['success'])
        self.assertEqual(known['q'], 53)

        n = 3233
        m = 65
        e1, e2 = 7, 11
        c1 = pow(m, e1, n)
        c2 = pow(m, e2, n)
        common = common_modulus_attack.attack(hex(n), str(e1), str(c1), str(e2), str(c2))
        self.assertTrue(common['success'])
        self.assertEqual(common['m'], m)
    
    def test_recursive_decryptor_initialization(self):
        """测试递归解密器初始化"""
        decryptor = AsyncRecursiveDecryptor(self.crypto_loader.decrypt_modules)
        self.assertIsNotNone(decryptor)

    def test_recursive_decrypt_uses_ciphertext_features(self):
        """测试递归解密优先使用密文特征命中的算法"""
        result = recursive_decrypt(
            '666c61677b746573747d',
            base_path=self.base_path,
            max_depth=2,
            max_results_per_depth=10,
            max_total_attempts=1000,
            brute_force_small_keyspaces=False,
        )

        self.assertIsNotNone(result['best'])
        self.assertEqual(result['best']['text'], 'flag{test}')
        self.assertEqual(result['best']['chain_summary'], 'hex')
        self.assertEqual(result['total_attempts'], 1)

    def test_recursive_decrypt_follows_nested_ciphertext_features(self):
        """测试多层递归按密文特征逐层缩小算法范围"""
        result = recursive_decrypt(
            'NjY2YzYxNjc3Yjc0NjU3Mzc0N2Q=',
            base_path=self.base_path,
            max_depth=3,
            max_results_per_depth=10,
            max_total_attempts=1000,
            brute_force_small_keyspaces=False,
        )

        self.assertIsNotNone(result['best'])
        self.assertEqual(result['best']['text'], 'flag{test}')
        self.assertEqual(result['best']['chain_summary'], 'Base64 → hex')
        self.assertLessEqual(result['total_attempts'], 5)

    def test_recursive_decrypt_reports_short_base64_candidate(self):
        """测试短 Base64 文本也能作为递归解密候选输出"""
        result = recursive_decrypt(
            'aGVsbG8=',
            base_path=self.base_path,
            max_depth=2,
            max_results_per_depth=10,
            max_total_attempts=1000,
            brute_force_small_keyspaces=False,
        )

        self.assertIsNone(result['best'])
        self.assertIsNotNone(result['best_candidate'])
        self.assertEqual(result['best_candidate']['text'], 'hello')
        self.assertEqual(result['best_candidate']['chain_summary'], 'Base64')

    def test_recursive_decrypt_uses_small_keyspace_bruteforce(self):
        """测试递归解密会对凯撒这类小密钥空间算法做爆破"""
        result = recursive_decrypt(
            'khoor zruog',
            base_path=self.base_path,
            max_depth=2,
            patterns=['hello'],
            max_results_per_depth=50,
            max_total_attempts=1000,
            brute_force_small_keyspaces=True,
        )

        self.assertIsNotNone(result['best'])
        self.assertEqual(result['best']['text'], 'hello world')
        self.assertEqual(result['best']['chain_summary'], 'caesar凯撒密码(shift=3)')

    def test_recursive_decrypt_supports_base58_chain(self):
        """测试递归解密可直接走通 Base58 链"""
        result = recursive_decrypt(
            '4356667445667A75535A4B555A6659356973626931724777314C4E75654172464472536F6D7841336E6666346D58746B72546259395476546A4C4466374E6A6475796B6B4B577535316E444B736A326534764E59364E7A754447675436376166537A3765454669777554644C534A48565A4C737A3470757951414C386E6575614C7A564A55744A4D6B69706258594E7445367946754E427950767969637A50434D347156644A48634B466570743574595A70566A4257564333446A36345A6553596B785339644A41414475567134574D5547366D6F785578535345366E5450375943436156523671424759',
            base_path=self.base_path,
            max_depth=10,
            max_results_per_depth=50,
            max_total_attempts=20000,
            brute_force_small_keyspaces=False,
        )

        self.assertIsNotNone(result['best'])
        self.assertIn('FLAG', result['best']['text'].upper())
        self.assertIn('Base58', result['best']['chain_summary'])
        self.assertEqual(result['best']['text'], 'flag{this_is=a+test-password}')

    def test_recursive_decrypt_prefers_short_keyword_chain(self):
        """测试关键词命中优先选择较短的可信链"""
        result = recursive_decrypt(
            '3X9CmfKNxdY8qKRu5zTkNECZcZasFbmuDSEj1nDpxxzkspSQvGjzZ7fqUqSi7FbpJU5tW1FVsXSLsgtmyN4VxjGppwTh2xV7rbjVabWqwSESBodzLxevn3vfmK6cywQ4DiskvsR96uNQWGHkmLaCs1XTxUvhYHPy5ZeDTfg68XaWZnu9N8ubkxJhUXNrY797REmDXPW6GHBwQXQr7WLYPzU8ACUajDLAmNHEtZrfShDN4YkxBqPBNKndi7htmximB6nYWH4C8ZAAosAREQcKpP9SEtrYFGgPtBdaERskmxEZ1NXDKGwMLop9VedYZpTTLipbUR29xm8Lo9uCc1ijeJp2PHh1GqW7dmsuu8bmw8f3sTX8EqyA9a9ytVjKFsdzcGRzEyhvHgTbjLCT8CpvjFj65V7x68iCwJJssQrmtjKeYH3ryaZT6NR2cR9JysDRKTXUgxqiKtN8DE2YThgyFaHdyVc8k9ZqipjbX1v4sNs6xZDpDKEnBuLhZQZh6NyNbaK2cPX8SRcpWmz4vvcUNTCJiC8kVhQfAWwQMA2CyfuNF5Kxa2HrgiZj4QomZbNQEG4vGLRuXBgTqfPteTUazNrsozfJZAUwn2GUSxqNLhkRJxrhk8W7DHAwsDRsB3mU2Sr8YezrWdDucRiok8GQH1SFFf5bGeQoRrUgtJQmmVCR15XoGL3VXWgaYRaUFSHfWrdtn6f61NhwWkoRUMUDNbxvgT7KCTSibvG6Bw8SbuSA3vwQ3wKytMw2GUQgaoT5iZWPTphFYNnhtKr1n4s',
            base_path=self.base_path,
            max_depth=10,
            max_results_per_depth=50,
            max_total_attempts=20000,
            brute_force_small_keyspaces=False,
        )

        self.assertIsNotNone(result['best'])
        self.assertEqual(result['best']['text'], 'QJGFLAGINKOBK3OBCJJEO25BOL1GOTUBNZMUM30X')
        self.assertEqual(result['best']['chain_summary'], 'Base58 → hex → Base32 → morse摩斯密码 → rot13')
     
    def test_ai_config(self):
        """测试AI配置"""
        config = AIConfig()
        self.assertIsNotNone(config)
        self.assertIn('provider', config.config)
        self.assertIn('api_key', config.config)


if __name__ == '__main__':
    unittest.main()
