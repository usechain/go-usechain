// Copyright 2018 The go-usechain Authors
// This file is part of the go-usechain library.
//
// The go-usechain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-usechain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-usechain library. If not, see <http://www.gnu.org/licenses/>.

package sssa

import (
	"errors"
	"math/big"
	"fmt"

	"github.com/usechain/go-usechain/crypto"
	"crypto/ecdsa"
)

var (
	ErrCannotRequireMoreShares = errors.New("cannot require more shares then existing")
	ErrOneOfTheSharesIsInvalid = errors.New("one of the shares is invalid")
)

const (
	DefaultPrivStr = "95792089237316195423570985008687907853269984665640"
	DefaultPrimeStr = "115792089237316195423570985008687907852837564279074904382605163141518161494337"
)

/**
 * Returns a new array of secret shares (encoding x,y pairs as base64 strings)
 * created by Shamir's Secret Sharing Algorithm requring a minimum number of
 * share to recreate, of length shares, from the input secret raw as a string
**/
func CreateFromInt(minimum int, shares int) ([]string, []*big.Int, []*big.Int, error) {
	// Verify minimum isn't greater than shares; there is no way to recreate
	// the original polynomial in our current setup, therefore it doesn't make
	// sense to generate fewer shares than are needed to reconstruct the secret.
	if minimum > shares {
		return []string{""}, []*big.Int{}, []*big.Int{}, ErrCannotRequireMoreShares
	}

	// Convert the secret to its respective 256-bit big.Int representation
	var secret []*big.Int = make([]*big.Int, 1)

	// Set constant prime across the package
	prime, _ = big.NewInt(0).SetString(DefaultPrimeStr, 10)
	secret[0] = randomInLimit()

	fmt.Println(secret)

	// List of currently used numbers in the polynomial
	var numbers []*big.Int = make([]*big.Int, 0)
	numbers = append(numbers, big.NewInt(0))

	// Create the polynomial of degree (minimum - 1); that is, the highest
	// order term is (minimum-1), though as there is a constant term with
	// order 0, there are (minimum) number of coefficients.
	//
	// However, the polynomial object is a 2d array, because we are constructing
	// a different polynomial for each part of the secret
	// polynomial[parts][minimum]
	var polynomial [][]*big.Int = make([][]*big.Int, len(secret))

	for i := range polynomial {
		polynomial[i] = make([]*big.Int, minimum)
		polynomial[i][0] = secret[i]

		for j := range polynomial[i][1:] {
			///TODO:add the  random part
			// Each coefficient should be unique

			number := randomInLimit()
			for inNumbers(numbers, number) {
				number = randomInLimit()
			}
			fmt.Printf("The prime :%d, %d\n", number, len(number.Bytes()))

			numbers = append(numbers, number)

			polynomial[i][j+1] = number
		}
	}

	// Create the secrets object; this holds the (x, y) points of each share.
	// Again, because secret is an array, each share could have multiple parts
	// over which we are computing Shamir's Algorithm. The last dimension is
	// always two, as it is storing an x, y pair of points.
	//
	// Note: this array is technically unnecessary due to creating result
	// in the inner loop. Can disappear later if desired. [TODO]
	//
	// secrets[shares][parts][2]
	var secrets [][][]*big.Int = make([][][]*big.Int, shares)
	var result []string = make([]string, shares)

	// For every share...
	for i := range secrets {
		secrets[i] = make([][]*big.Int, len(secret))
		// ...and every part of the secret...
		for j := range secrets[i] {
			secrets[i][j] = make([]*big.Int, 2)

			// ...generate a new x-coordinate...
			number := random()
			for inNumbers(numbers, number) {
				number = random()
			}
			numbers = append(numbers, number)

			// ...and evaluate the polynomial at that point...
			secrets[i][j][0] = number
			secrets[i][j][1] = evaluatePolynomial(polynomial[j], number)

			// ...add it to results...
			result[i] += toBase64(secrets[i][j][0])
			result[i] += toBase64(secrets[i][j][1])
		}
	}

	// For get fi(j)
	index := big.NewInt(1)
	var pointer []*big.Int= make([]*big.Int, shares)
	for i := range secrets {
		// ...and every part of the secret...
		for j := range secrets[i] {
			pointer[i] = evaluatePolynomial(polynomial[j], index)
			fmt.Printf("The number is %d, f(%d):%x\n:", index, index, pointer[i])
		}
		index.Add(index, big.NewInt(1))
	}

	// ...and return!
	return result, pointer, polynomial[0], nil
}

/**
 * Returns a new arary of secret shares (encoding x,y pairs as base64 strings)
 * created by Shamir's Secret Sharing Algorithm requring a minimum number of
 * share to recreate, of length shares, from the input secret raw as a string
**/
func Create(minimum int, shares int, raw string) ([]string, []*big.Int, []*big.Int, error) {
	// Verify minimum isn't greater than shares; there is no way to recreate
	// the original polynomial in our current setup, therefore it doesn't make
	// sense to generate fewer shares than are needed to reconstruct the secret.
	if minimum > shares {
		return []string{""}, []*big.Int{}, []*big.Int{}, ErrCannotRequireMoreShares
	}

	// Convert the secret to its respective 256-bit big.Int representation
	var secret []*big.Int = splitByteToInt([]byte(raw))
	fmt.Println("secret:", secret)

	// Set constant prime across the package
	prime, _ = big.NewInt(0).SetString(DefaultPrimeStr, 10)
	test := random()
	secret[0] = test
	fmt.Println(secret)

	// List of currently used numbers in the polynomial
	var numbers []*big.Int = make([]*big.Int, 0)
	numbers = append(numbers, big.NewInt(0))

	// Create the polynomial of degree (minimum - 1); that is, the highest
	// order term is (minimum-1), though as there is a constant term with
	// order 0, there are (minimum) number of coefficients.
	//
	// However, the polynomial object is a 2d array, because we are constructing
	// a different polynomial for each part of the secret
	// polynomial[parts][minimum]
	var polynomial [][]*big.Int = make([][]*big.Int, len(secret))
	maxPolynomial, _ := big.NewInt(0).SetString("18577701560408869159165164103615505429330560073505879322283895478251523783470", 10)


	for i := range polynomial {
		polynomial[i] = make([]*big.Int, minimum)
		polynomial[i][0] = secret[i]

		for j := range polynomial[i][1:] {
			///TODO:add the  random part
			// Each coefficient should be unique

			number := random()
			for inNumbers(numbers, number) || number.Cmp(maxPolynomial) == 1{
				number = random()
			}
			fmt.Printf("The prime :%d, %d\n", number, len(number.Bytes()))

			numbers = append(numbers, number)

			polynomial[i][j+1] = number
		}
	}

	// Create the secrets object; this holds the (x, y) points of each share.
	// Again, because secret is an array, each share could have multiple parts
	// over which we are computing Shamir's Algorithm. The last dimension is
	// always two, as it is storing an x, y pair of points.
	//
	// Note: this array is technically unnecessary due to creating result
	// in the inner loop. Can disappear later if desired. [TODO]
	//
	// secrets[shares][parts][2]
	var secrets [][][]*big.Int = make([][][]*big.Int, shares)
	var result []string = make([]string, shares)

	// For every share...
	for i := range secrets {
		secrets[i] = make([][]*big.Int, len(secret))
		// ...and every part of the secret...
		for j := range secrets[i] {
			secrets[i][j] = make([]*big.Int, 2)

			// ...generate a new x-coordinate...
			number := random()
			for inNumbers(numbers, number) {
				number = random()
			}
			numbers = append(numbers, number)

			// ...and evaluate the polynomial at that point...
			secrets[i][j][0] = number
			secrets[i][j][1] = evaluatePolynomial(polynomial[j], number)

			// ...add it to results...
			result[i] += toBase64(secrets[i][j][0])
			result[i] += toBase64(secrets[i][j][1])
		}
	}

	// For get fi(j)
	index := big.NewInt(1)
	var pointer []*big.Int= make([]*big.Int, shares)
	for i := range secrets {
		// ...and every part of the secret...
		for j := range secrets[i] {
			pointer[i] = evaluatePolynomial(polynomial[j], index)
			fmt.Printf("The number is %d, f(%d):%x\n:", index, index, pointer[i])
		}
		index.Add(index, big.NewInt(1))
	}

	// ...and return!
	return result, pointer, polynomial[0], nil
}

/**
 * Takes a string array of shares encoded in base64 created via Shamir's
 * Algorithm; each string must be of equal length of a multiple of 88 characters
 * as a single 88 character share is a pair of 256-bit numbers (x, y).
 *
 * Note: the polynomial will converge if the specified minimum number of shares
 *       or more are passed to this function. Passing thus does not affect it
 *       Passing fewer however, simply means that the returned secret is wrong.
**/
func Combine(shares []string) (string, error) {
	// Recreate the original object of x, y points, based upon number of shares
	// and size of each share (number of parts in the secret).
	var secrets [][][]*big.Int = make([][][]*big.Int, len(shares))

	// Set constant prime
	prime, _ = big.NewInt(0).SetString(DefaultPrimeStr, 10)

	// For each share...
	for i := range shares {
		// ...ensure that it is valid...
		if IsValidShare(shares[i]) == false {
			return "", ErrOneOfTheSharesIsInvalid
		}

		// ...find the number of parts it represents...
		share := shares[i]
		count := len(share) / 88
		secrets[i] = make([][]*big.Int, count)

		// ...and for each part, find the x,y pair...
		for j := range secrets[i] {
			cshare := share[j*88 : (j+1)*88]
			secrets[i][j] = make([]*big.Int, 2)
			// ...decoding from base 64.
			secrets[i][j][0] = fromBase64(cshare[0:44])
			secrets[i][j][1] = fromBase64(cshare[44:])
			fmt.Println("secrets[i][j][1]", cshare[44:])
		}
	}

	// Use Lagrange Polynomial Interpolation (LPI) to reconstruct the secret.
	// For each part of the secert (clearest to iterate over)...
	var secret []*big.Int = make([]*big.Int, len(secrets[0]))
	for j := range secret {
		secret[j] = big.NewInt(0)
		// ...and every share...
		for i := range secrets { // LPI sum loop
			// ...remember the current x and y values...
			origin := secrets[i][j][0]
			originy := secrets[i][j][1]
			numerator := big.NewInt(1)   // LPI numerator
			denominator := big.NewInt(1) // LPI denominator
			// ...and for every other point...
			for k := range secrets { // LPI product loop
				if k != i {
					// ...combine them via half products...
					current := secrets[k][j][0]
					negative := big.NewInt(0)
					negative = negative.Mul(current, big.NewInt(-1))
					added := big.NewInt(0)
					added = added.Sub(origin, current)

					numerator = numerator.Mul(numerator, negative)
					numerator = numerator.Mod(numerator, prime)

					denominator = denominator.Mul(denominator, added)
					denominator = denominator.Mod(denominator, prime)
				}
			}

			// LPI product
			// ...multiply together the points (y)(numerator)(denominator)^-1...
			working := big.NewInt(0).Set(originy)
			working = working.Mul(working, numerator)
			working = working.Mul(working, modInverse(denominator))
			fmt.Printf("numerator: %x, denominator: %x\n", numerator, denominator)

			working = working.Mod(working, prime)
			fmt.Printf("secret[%d]: %x\n", j, working)
			// LPI sum
			secret[j] = secret[j].Add(secret[j], working)
			secret[j] = secret[j].Mod(secret[j], prime)
		}
	}
	fmt.Printf("secret: %x\n", secret)
	// ...and return the result!
	return string(mergeIntToByte(secret)), nil
}

/**
 * Takes a string array of shares encoded in base64 created via Shamir's
 * Algorithm; each string must be of equal length of a multiple of 88 characters
 * as a single 88 character share is a pair of 256-bit numbers (x, y).
 *
 * Note: the polynomial will converge if the specified minimum number of shares
 *       or more are passed to this function. Passing thus does not affect it
 *       Passing fewer however, simply means that the returned secret is wrong.
 * (t_1* b_1)G + (t_2 * b_2)G
**/
func CombinePubFirst(shares []string) (string, error) {
	// Recreate the original object of x, y points, based upon number of shares
	// and size of each share (number of parts in the secret).
	var secrets [][][]*big.Int = make([][][]*big.Int, len(shares))
	var secretPubs []ecdsa.PublicKey = make([]ecdsa.PublicKey, len(shares))

	// Set constant prime
	prime, _ = big.NewInt(0).SetString(DefaultPrimeStr, 10)

	// For each share...
	for i := range shares {
		// ...ensure that it is valid...
		if IsValidShare(shares[i]) == false {
			return "", ErrOneOfTheSharesIsInvalid
		}

		// ...find the number of parts it represents...
		share := shares[i]
		count := len(share) / 88
		secrets[i] = make([][]*big.Int, count)

		// ...and for each part, find the x,y pair...
		for j := range secrets[i] {
			cshare := share[j*88 : (j+1)*88]
			secrets[i][j] = make([]*big.Int, 2)
			// ...decoding from base 64.
			secrets[i][j][0] = fromBase64(cshare[0:44])
			secrets[i][j][1] = fromBase64(cshare[44:])
			fmt.Println("secrets[i][j][1]", cshare[44:])
		}
	}

	// Use Lagrange Polynomial Interpolation (LPI) to reconstruct the secret.
	// For each part of the secert (clearest to iterate over)...
	var secret []*big.Int = make([]*big.Int, len(secrets[0]))
	for j := range secret {
		secret[j] = big.NewInt(0)
		// ...and every share...
		for i := range secrets { // LPI sum loop
			// ...remember the current x and y values...
			origin := secrets[i][j][0]
			originy := secrets[i][j][1]
			numerator := big.NewInt(1)   // LPI numerator
			denominator := big.NewInt(1) // LPI denominator
			// ...and for every other point...
			for k := range secrets { // LPI product loop
				if k != i {
					// ...combine them via half products...
					current := secrets[k][j][0]
					negative := big.NewInt(0)
					negative = negative.Mul(current, big.NewInt(-1))
					added := big.NewInt(0)
					added = added.Sub(origin, current)

					numerator = numerator.Mul(numerator, negative)
					numerator = numerator.Mod(numerator, prime)

					denominator = denominator.Mul(denominator, added)
					denominator = denominator.Mod(denominator, prime)
				}
			}

			// LPI product
			// ...multiply together the points (y)(numerator)(denominator)^-1...
			working := big.NewInt(0).Set(originy)
			working = working.Mul(working, numerator)
			working = working.Mul(working, modInverse(denominator))
			fmt.Printf("numerator: %x, denominator: %x\n", numerator, denominator)

			working = working.Mod(working, prime)
			fmt.Printf("Test secret[%d]: %x\n", i, working)

			secretPubs[i] = getPublicKey(working)

			// LPI sum
			fmt.Printf(":::::::::%x, %x\n", secret[j], working)
			secret[j] = secret[j].Add(secret[j], working)
			fmt.Printf("sum[j]: %x\n", secret[j])
			secret[j] = secret[j].Mod(secret[j], prime)
		}
	}
	fmt.Printf("secret: %x\n", secret)

	demoPubInt, _ := big.NewInt(1).SetString("a5fe2655dee1eefc990ab09573b0c962f7ea82077e5451a6aa1ce412c81ad17c", 16)
	demoPub := getPublicKey(demoPubInt)
	fmt.Println("demoPub", demoPub)

	demoPubInt2, _ := big.NewInt(1).SetString("88fc57bff14cf016e32f5bf86444d496ff909e66c5b7be212bac181f9f40e68f", 16)
	demoPub2 := getPublicKey(demoPubInt2)
	fmt.Println("demoPub", demoPub2)

	demoSum := new(ecdsa.PublicKey)
	demoSum.Curve = crypto.S256()
	demoSum.X, demoSum.Y = crypto.S256().Add(demoPub.X, demoPub.Y, demoPub2.X, demoPub2.Y)
	fmt.Println("demoSum", demoSum)

	demoSumInt2, _ := big.NewInt(1).SetString("2efa7e15d02edf137c3a0c8dd7f59dfb3ccc438794c36f8c15f69da5972576ca", 16)
	demoSum2 := getPublicKey(demoSumInt2)
	fmt.Println("demoPub", demoSum2)

	fmt.Println("pub genrate okay!!!")
	res := new(ecdsa.PublicKey)
	res.Curve = crypto.S256()
	res.X, res.Y = crypto.S256().Add(secretPubs[0].X, secretPubs[0].Y, secretPubs[1].X, secretPubs[1].Y)

	fmt.Println("res:", res)
	// ...and return the result!
	return string(mergeIntToByte(secret)), nil
}

/**
 * Takes a string array of shares encoded in base64 created via Shamir's
 * Algorithm; each string must be of equal length of a multiple of 88 characters
 * as a single 88 character share is a pair of 256-bit numbers (x, y).
 *
 * Note: the polynomial will converge if the specified minimum number of shares
 *       or more are passed to this function. Passing thus does not affect it
 *       Passing fewer however, simply means that the returned secret is wrong.
**/
func CombineECDSAPubs(shares []string) (string, error) {
	// Recreate the original object of x, y points, based upon number of shares
	// and size of each share (number of parts in the secret).
	var secrets [][][]*big.Int = make([][][]*big.Int, len(shares))
	var secretPubs []*ecdsa.PublicKey = make([]*ecdsa.PublicKey, len(shares))

	// Set constant prime
	prime, _ = big.NewInt(0).SetString(DefaultPrimeStr, 10)


	fmt.Println("CombineECDSAPubs", shares)
	// For each share...
	for i := range shares {
		// ...ensure that it is valid...

		if IsValidShare(shares[i]) == false {
			return "", ErrOneOfTheSharesIsInvalid
		}

		// ...find the number of parts it represents...
		share := shares[i]
		fmt.Printf("shares[%d]:%x\n", i, share)
		count := len(share) / 132
		secrets[i] = make([][]*big.Int, count)

		// ...and for each part, find the x,y pair...
		for j := range secrets[i] {
			cshare := share[j*132 : (j+1)*132]
			secrets[i][j] = make([]*big.Int, 3)
			// ...decoding from base 64.
			secrets[i][j][0] = fromBase64(cshare[0:44])
			secrets[i][j][1] = fromBase64(cshare[44:88])
			secrets[i][j][2] = fromBase64(cshare[88:])
		}
	}
	fmt.Println("shares generate already!!!!")
	// Use Lagrange Polynomial Interpolation (LPI) to reconstruct the secret.
	// For each part of the secert (clearest to iterate over)...
	var secret []*big.Int = make([]*big.Int, len(secrets[0]))
	for j := range secret {
		secret[j] = big.NewInt(0)
		// ...and every share...
		for i := range secrets { // LPI sum loop
			// ...remember the current x and y values...
			origin := secrets[i][j][0]
			origin_x := secrets[i][j][1]
			origin_y := secrets[i][j][2]
			numerator := big.NewInt(1)   // LPI numerator
			denominator := big.NewInt(1) // LPI denominator
			// ...and for every other point...
			for k := range secrets { // LPI product loop
				if k != i {
					// ...combine them via half products...
					current := secrets[k][j][0]
					negative := big.NewInt(0)
					negative = negative.Mul(current, big.NewInt(-1))
					added := big.NewInt(0)
					added = added.Sub(origin, current)

					numerator = numerator.Mul(numerator, negative)
					numerator = numerator.Mod(numerator, prime)

					denominator = denominator.Mul(denominator, added)
					denominator = denominator.Mod(denominator, prime)
				}
			}

			// LPI product
			// ...multiply together the points (y)(numerator)(denominator)^-1...
			// but as origin_x & origin_y is a point on elliptic Curve
			param := numerator.Mul(numerator, modInverse(denominator))
			fmt.Printf("param:%x\n", param)
			param = param.Mod(param, prime)
			fmt.Printf("numerator: %x, denominator: %x\n", numerator, denominator)

			A1 := new(ecdsa.PublicKey)
			A1.Curve = crypto.S256()
			A1.X, A1.Y = crypto.S256().ScalarMult(origin_x, origin_y, param.Bytes())   //A1=b_1 * (t_1 * G)

			// LPI sum
			secretPubs[i] = A1
			fmt.Printf("secretPubs[%d]: %x\n", i, A1)
		}
	}
	fmt.Println("pub genrate okay!!!")
	res := new(ecdsa.PublicKey)
	res.Curve = crypto.S256()
	if secretPubs[0].X == nil || secretPubs[1].X == nil {
		return "", ErrOneOfTheSharesIsInvalid
	}
	res.X, res.Y = crypto.S256().Add(secretPubs[0].X, secretPubs[0].Y, secretPubs[1].X, secretPubs[1].Y)
	fmt.Println("res:", res)

	// ...and return the result!
	return string(crypto.FromECDSAPub(res)), nil
}

/**
 * Takes in a given string to check if it is a valid secret
 *
 * Requirements:
 * 	Length multiple of 88
 *	Can decode each 44 character block as base64
 *
 * Returns only success/failure (bool)
**/
func IsValidShare(candidate string) bool {
	// Set constant prime across the package
	prime, _ = big.NewInt(0).SetString(DefaultPrimeStr, 10)
	fmt.Println("The length of the candidate:", len(candidate))

	if len(candidate)%88 != 0 && len(candidate)%132 != 0{
		return false
	}

	count := len(candidate) / 44
	for j := 0; j < count; j++ {
		part := candidate[j*44 : (j+1)*44]
		decode := fromBase64(part)
		if decode.Cmp(big.NewInt(0)) == -1 || decode.Cmp(prime) == 1 {
			return false
		}
	}

	return true
}
