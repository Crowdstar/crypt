<?php
/**
 * Copyright 2021 Glu Mobile Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

declare(strict_types=1);

namespace CrowdStar\Tests;

use CrowdStar\Crypt\Crypt;
use CrowdStar\Crypt\Exception;
use PHPUnit\Framework\TestCase;

/**
 * Tests for class \CrowdStar\Crypt\Crypt.
 *
 * @internal
 * @coversNothing
 */
class CryptTest extends TestCase
{
    protected const TEST_DATA = 'test_message';

    protected const TEST_KEY1 = '1234567890123456';

    protected const TEST_KEY2 = '9876543210123456';

    public function dataEncryption(): array
    {
        return [
            [
                44,
                self::TEST_DATA,
                self::TEST_KEY1,
                'Encrypt a string with the first key.',
            ],
            [
                44,
                self::TEST_DATA,
                self::TEST_KEY2,
                'Encrypt a string with the second key.',
            ],
        ];
    }

    /**
     * @dataProvider dataEncryption
     * @covers \CrowdStar\Crypt\Crypt::encrypt
     */
    public function testEncryption(int $expectedLength, string $data, string $key, string $message)
    {
        $encryptedData = (new Crypt($key))->encrypt($data);

        $cipherText = substr(base64_decode($encryptedData), 0, -Crypt::DEFAULT_IV_LENGTH);
        // does not measure security but ensures the cipher text is some distance away from the original message
        self::assertGreaterThan(5, levenshtein($data, $cipherText));

        self::assertSame($expectedLength, strlen($encryptedData), $message);
    }

    public function dataDecryption(): array
    {
        return [
            [
                '',
                '',
                self::TEST_KEY1,
                'Decrypt an empty string.',
            ],
            [
                '',
                'invalid-key',
                self::TEST_KEY1,
                'Decrypt a invalid base64-encoded string.',
            ],
            [
                '',
                'YQ==',
                self::TEST_KEY1,
                'Decrypt a short string (a bad encrypted string; base64-encoded).',
            ],
            [
                '',
                'OGs3emdkaTlqd3ltMmh6Y21ubjJqMmp5Y25sMDU1ZHhsOWNod2poZWU3MG8=',
                self::TEST_KEY1,
                'Decrypt a long string "8k7zgdi9jwym2hzcmnn2j2jycnl055dxl9chwjhee70o" (a bad encrypted string; base64-encoded).',
            ],

            [
                self::TEST_DATA,
                'Btpxr9R00y2/69lseobzCPCv95ru0yvbN2tzGZphmqs=',
                self::TEST_KEY1,
                'Decrypt a string with the first key (the correct one).',
            ],
            [
                self::TEST_DATA,
                'LbdYEJg0GjBl7aVqhFu+QpwabowYX87qy/9itTu8nOE=',
                self::TEST_KEY1,
                'Decrypt another string with the first key (the correct one).',
            ],
            [
                '',
                'Btpxr9R00y2/69lseobzCPCv95ru0yvbN2tzGZphmqs=',
                self::TEST_KEY2,
                'Decrypt a string with the second key (the wrong one).',
            ],
        ];
    }

    /**
     * @dataProvider dataDecryption
     * @covers \CrowdStar\Crypt\Crypt::decrypt
     */
    public function testDecryption(string $expectedData, string $encryptedData, string $key, string $message)
    {
        self::assertSame($expectedData, (new Crypt($key))->decrypt($encryptedData), $message);
    }

    /**
     * @covers \CrowdStar\Crypt\Crypt::generateIV
     */
    public function testBadIVLength()
    {
        self::expectException(Exception::class);
        self::expectExceptionMessage('The length of the desired string of bytes must be a positive integer.');

        (new Crypt(static::TEST_KEY1))->encrypt('test_message', 0);
    }
}
