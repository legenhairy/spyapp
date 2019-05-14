import UIKit

protocol CipherProtocol {
    func encrypt(plaintext: String, secret: String) -> String
    func decrypt(plaintext: String, secret: String) -> String
}

struct CesarCipher: CipherProtocol {
    func encrypt(plaintext: String, secret: String) -> String {
        guard let secretInt = UInt32(secret) else {
            return "Error"
        }
        var encoded = ""
        for character in plaintext {
            guard let firstUnicodeScalar = character.unicodeScalars.first else {
                continue
            }
            let unicode = firstUnicodeScalar.value
            let shiftedUnicode = unicode + secretInt
            let shiftedCharacter = String(UnicodeScalar(UInt8(shiftedUnicode)))

            encoded += shiftedCharacter
        }
        return encoded
    }

    func decrypt(plaintext: String, secret: String) -> String {
        
        guard let secretInt = UInt32(secret) else {
            return "An issue occured with decrypt"
        }
        var decoded = ""
        for character in plaintext {
            guard let firstUnicodeScalar = character.unicodeScalars.first else {
                continue
            }
            let unicode = firstUnicodeScalar.value
            let shiftedUnicode = unicode - secretInt
            let shiftedCharacter = String(UnicodeScalar(UInt8(shiftedUnicode)))
            
            decoded += shiftedCharacter
        }
        return decoded
    }

}
/*
 it will only accept a to z, A to Z, 0 to 9
 decode will return uppercase
 decode can accept lowercase letters
 */

struct AlphanumericCesarCipher: CipherProtocol {
    
    func encrypt(plaintext: String, secret: String) -> String {
        guard let shiftBy = UInt32(secret) else {
            return ""
        }
        var encoded = ""
        let newplaintext = plaintext.uppercased()
        
        for character in newplaintext {
            let unicode = character.unicodeScalars.first!.value
            
            /*check that input is only alphanumeric */
            /*unicode value 48 refers to 0, 122 refers to ,*/
            if(unicode < 48 || unicode > 122 || (unicode > 57 && unicode < 65)) {
                return "Error: input has invalid characters"
            }
            var shiftedUnicode = unicode + shiftBy
            
            //Z to 0, 9 to A, cyclical mapping in either direction
            
            if shiftBy > 0 && shiftedUnicode > 90 {
                shiftedUnicode = shiftedUnicode - 43
            } else if shiftBy > 0 && shiftedUnicode > 57 && shiftedUnicode < 65 {
                shiftedUnicode = shiftedUnicode + 7 /*9 mapping to A if shift > 0*/
            } else if shiftBy < 0 && shiftedUnicode < 48 { /*0 maps to Z*/
                shiftedUnicode = shiftedUnicode + 43
            } else if shiftBy > 0 && shiftedUnicode > 57 && shiftedUnicode < 65 { /*A maps to 9*/
                shiftedUnicode = shiftedUnicode - 7
            }
            
            let shiftedCharacter = String(UnicodeScalar(UInt8(shiftedUnicode)))
            encoded = encoded + shiftedCharacter
        }
        
        return encoded
    }
    
    func decrypt(plaintext: String, secret: String) -> String {
        guard let shiftBy = UInt32(secret) else {
            return ""
        }
        
        var decoded = ""
        let newplaintext = plaintext.uppercased()
        
        for character in newplaintext {
            let unicode = character.unicodeScalars.first!.value
            /*don't need to check for invalid characters because we already did that for the input*/
            
            var shiftedUnicode = unicode - shiftBy
            
            //Z to 0, 9 to A
            
            if shiftBy > 0 && shiftedUnicode > 90 {
                shiftedUnicode = shiftedUnicode - 43
            } else if shiftBy > 0 && shiftedUnicode > 57 && shiftedUnicode < 65 {
                shiftedUnicode = shiftedUnicode + 7
            } else if shiftBy < 0 && shiftedUnicode < 48 {
                shiftedUnicode = shiftedUnicode + 43
            } else if shiftBy > 0 && shiftedUnicode > 57 && shiftedUnicode < 65 { 
                shiftedUnicode = shiftedUnicode - 7
            }
            
            let shiftedCharacter = String(UnicodeScalar(UInt8(shiftedUnicode)))
            decoded = decoded + shiftedCharacter
        }
        
        return decoded
    }

}
/*shift everything 10 to right, limit between ascii code 48-126*/
/*any input except spaces will be accepted*/
struct Shift10_Cipher : CipherProtocol {
    
    func encrypt(plaintext: String, secret: String) -> String {
        
        var encoded = ""
        /*secret value won't be used here*/
        for character in plaintext {
            
            let unicode = character.unicodeScalars.first!.value
            if unicode == 32 {
                return "Error: Input has spaces"
            } else if unicode < 48 {
                return "Error: Input has invalid characters(no characters like !,#,$,+)"
            }
    
            var shiftedUnicode = unicode + 10
            
            if shiftedUnicode > 126 {
                shiftedUnicode = shiftedUnicode - 79/*lowest case is ascii code 48*/
            }
            
            let shiftedCharacter = String(UnicodeScalar(UInt8(shiftedUnicode)))
            encoded = encoded + shiftedCharacter
            
        }
        
        return encoded
    }
    
    func decrypt(plaintext: String, secret: String) -> String {
        
        var decoded = ""
        
        for character in plaintext {
            
            let unicode = character.unicodeScalars.first!.value
            var shiftedUnicode = unicode - 10
            
            if shiftedUnicode < 48 {
                shiftedUnicode = shiftedUnicode + 79
            }
            
            let shiftedCharacter = String(UnicodeScalar(UInt8(shiftedUnicode)))
            decoded = decoded + shiftedCharacter
        }
        
        
        return decoded
    }
    
    
}
/*shift everything 5 to the right, limit between 48-126*/
/*no spaces allowed in input field*/

struct Shift5_Cipher: CipherProtocol {
    func encrypt(plaintext: String, secret: String) -> String {
        var encoded = ""
        
        for character in plaintext {
            
            let unicode = character.unicodeScalars.first!.value
            if unicode == 32 {
                return "Error: Input has spaces"
            } else if unicode < 48 {
                return "Error: Input has invalid characters"
            }
            
            var shiftedUnicode = unicode + 5
            
            if shiftedUnicode > 126 {
                shiftedUnicode = shiftedUnicode - 79/*lowest case is ascii code 48*/
            }
            
            let shiftedCharacter = String(UnicodeScalar(UInt8(shiftedUnicode)))
            encoded = encoded + shiftedCharacter
        }
        return encoded
    }
    
    func decrypt(plaintext: String, secret: String) -> String {
        var decoded = ""
        
        for character in plaintext {
            
            let unicode = character.unicodeScalars.first!.value
            var shiftedUnicode = unicode - 5
            
            if shiftedUnicode < 48 {
                shiftedUnicode = shiftedUnicode + 79
            }
            
            let shiftedCharacter = String(UnicodeScalar(UInt8(shiftedUnicode)))
            decoded = decoded + shiftedCharacter
        
        }
        return decoded
    }
    
}


class ViewController: UIViewController {

    @IBOutlet weak var inputField: UITextField!
    @IBOutlet weak var secretField: UITextField!
    @IBOutlet weak var output: UILabel!

    var cipher: CipherProtocol?
    let factory = CipherFactory()
    
    /*for initializing the secet text field to nothing for the 3rd and 4th ciphers*/
    var secretText: String {
        if let text = secretField.text {
            return text
        } else {
            return ""
        }
    }
    
    @IBAction func encryptButtonPressed(_ sender: Any) {
        guard
            let plaintext = inputField.text
        else {
            output.text = "No values provided"
            return
        }
        if let encoded = cipher?.encrypt(plaintext: plaintext, secret: secretText) {
            output.text = encoded
        } else {
            output.text = "Error encoding"
        }
    }

    @IBAction func decryptButtonPressed(_ sender: Any) {
        guard
            let plaintext = inputField.text
        else {
            output.text = "No values provided"
            return
        }
        if let decoded = cipher?.decrypt(plaintext: plaintext, secret: secretText) {
            output.text = decoded
        } else {
            output.text = "Error encoding"
        }
    }
    
    
    @IBAction func cipherSelected(_ sender: UIButton) {
        guard let buttonText = sender.titleLabel?.text else{
            return
        }
        
        cipher = factory.selectCipher(for: buttonText)
    }



}
