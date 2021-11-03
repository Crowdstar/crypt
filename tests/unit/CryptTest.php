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
    protected const TEST_KEY = '1234567890123456';

    /**
     * @covers \CrowdStar\Crypt\Crypt::decrypt
     * @covers \CrowdStar\Crypt\Crypt::encrypt
     */
    public function testEncryptionDecryption()
    {
        $testMessage = 'test_message';
        $crypt       = new Crypt(static::TEST_KEY);

        $encodedData = $crypt->encrypt($testMessage);

        // ensure message is encrypted
        $data       = base64_decode($encodedData);
        $cipherText = substr($data, 0, -Crypt::DEFAULT_IV_LENGTH);

        // does not measure security but ensures the cipher text is some distance away from the original message
        self::assertGreaterThan(5, levenshtein($testMessage, $cipherText));

        // ensure message is decrypted correctly
        self::assertEquals($testMessage, $crypt->decrypt($encodedData));
    }

    /**
     * @covers \CrowdStar\Crypt\Crypt::generateIV
     */
    public function testBadIVLength()
    {
        self::expectException(Exception::class);
        self::expectExceptionMessage('The length of the desired string of bytes must be a positive integer.');

        (new Crypt(static::TEST_KEY))->encrypt('test_message', 0);
    }
}
