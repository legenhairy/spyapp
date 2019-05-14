//
//  CipherFactory.swift
//  spyapp
//
//  Created by Harry Zhang on 4/12/19.
//  Copyright © 2019 Harry Zhang. All rights reserved.
//

import Foundation

struct CipherFactory {
    
    var ciphers: [String: CipherProtocol] = [
        "Cesar": CesarCipher(),
        "Alphanumeric": AlphanumericCesarCipher(),
        "Shift10": Shift10_Cipher(),
        "Shift5": Shift5_Cipher(),
    ]
    
    func selectCipher(for key: String) -> CipherProtocol {
        return ciphers[key]!
    }
    
}
