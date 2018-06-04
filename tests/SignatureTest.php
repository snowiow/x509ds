<?php

namespace X509DS\Tests;

use Codeception\Specify;
use PHPUnit\Framework\TestCase;
use X509DS\Exceptions\AlgorithmException;
use X509DS\PrivateKey;
use X509DS\Signature;

class SignatureTest extends TestCase
{
    use Specify;

    private const PKEY = __DIR__ . '/resources/private.key';

    public function testCalculate()
    {
        $this->describe('signature', function () {
            $this->should('accept sha1 as a method', function () {
                $sig = new Signature();
                $pkey = PrivateKey::fromPath(self::PKEY);
                $this->assertEquals(
                    'dtyOl1mU09QEUPqDVvT+Zv1z4q3JFMtB0nOEYqUCCrB+gtpcfbUYp48DmrdgKoAJ4hb4DTXadhagqKf9I7yW4GjK2zcq35626pS0tAJ+NYsC2DUoH+Kft55uyvTuCtYpph890sIPhALLrDtXGqaRqqVBUpdYyXM3J/S7CyPnoFCHccU93WRaYrwGgDUy6ZHduPfSnlvSvlR9sQmJyCveXeVEDSLbxrt/99xiWblDkJthIDP0va7U5WiU1AFxhWrgC9hXaTcjhbx7w6KlszWes4bjFuQC0110ZPbUe5b3HU7ao0bD3B58lwaes5dZdxWvbHdcdGKjv2LuPQCur6HiOw==',
                    $sig->calculate('this is a test', $pkey)
                );
            });
            $this->should('accept sha256 as a method', function () {
                $sig = new Signature(Signature::SHA256);
                $pkey = PrivateKey::fromPath(self::PKEY);
                $this->assertEquals(
                    '3msNWXBoPpekQremsBoKtg2dNKTB8eRocG/pfpYR+aF6o/dqFimLHAirokf3qyfEeOEzTm6VuEjWOFzlB1UEZzVNfkaP4bGx49CFp+J/Y6THO7SxOVcKULc4FG3GIayMjLkXOQrfx0nqnpmMkoVe29ij3Gv/rmcMFGRwBvVViZpaDNOUEcGtYnP152zGx01H36PTHXSP5MT5T5KIuomOpSjL+gUHWIbGyjY/ufLjqp8qhsAVnHvfNejUOK/qc+IlTW4+SJxcXIXz/GeBMocZ6gOuaHdAqM38Q45mEV+nB1A4dhoRkNaL0DhsNso/jNuW9zTU9jkEKmj1Kok1J5pioA==',
                    $sig->calculate('this is a test', $pkey)
                );
            });
            $this->should('accept sha512 as a method', function () {
                $sig = new Signature(Signature::SHA512);
                $pkey = PrivateKey::fromPath(self::PKEY);
                $this->assertEquals(
                    'Wiif0B2cM0FdOcujFBcP0Ophz9OxIO/d0GiwHvf3l12yrDkD3rqMFaRBWSoC17t5wEPJnAUl6C3sFQkZuwJRiCVPcozpUOO2FtxOUjiT5EIrrWRM/QP3h+Jvw6jcR9Yfq3xR5W9xoP//ejAqWGdTSwFtz1SUgqIC/WXeKwIaCBeV6awyNqN8uRHKbH0eZ8g2gxaxNg6BjZiuflXKtqAv3ZV4STdtLocQVx7O//xt4BkszfjqGjpgvjnZ0bcXveRJR0Fvngk01dvWMQzJt3tjmkrLLewDoRz+O7CLFnvPM6xBr8Yil/x+Mqnn73znYO6VLd65CNITpVzVCsc/KzMH8Q==',
                    $sig->calculate('this is a test', $pkey)
                );
            });
            $this->should('accept ripemd160 as a method', function () {
                $sig = new Signature(Signature::RIPEMD160);
                $pkey = PrivateKey::fromPath(self::PKEY);
                $this->assertEquals(
                    'QcJaVIgOJhoSrS8WdJHiGCruyHSDmej8QNii2fKTt1Ue1My1r9XhGxcRz6Dc8Gf7x+aD1gEmIWpKR/mJ2jkvXePvk44M/gbpEXYmLR3SIONzDMJOp12fA8A0Z8R01NcESTaxIUvXLgHs3XVVprHGcqBqM9Z2TtXvavHSMnz4NoM4rwx2oIzsL9O9N8wjCd+gUfbO7fsALDzJVfdJDiYvFTcbnHDEtZKlRCKcswT+MyDdGvaU1DR29YuycvoiDU1k1569C+SelHlwbN8mo+oPWUc/Oz+DWDrSioRqAzY78gW2lfFkdO10XNqU/XrflpEFJWp/w8IU1zB1jAGU6II4cQ==',
                    $sig->calculate('this is a test', $pkey)
                );
            });
            $this->should('throw an AlgorithmException if an unknown method is given', function () {
                $this->expectException(AlgorithmException::class);
                $sig = new Signature('repemd256');
                $pkey = PrivateKey::fromPath(self::PKEY);
                $sig->calculate('this is a test', $pkey);
            });
        });
    }
}
