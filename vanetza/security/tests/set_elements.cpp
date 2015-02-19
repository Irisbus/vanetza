#include <vanetza/security/tests/set_elements.hpp>

EccPoint setEccPoint_uncompressed() {
    EccPoint point;
    Uncompressed uncompressed;
    for (int c = 0; c < 32; c++) {
        uncompressed.x.push_back(c);
        uncompressed.y.push_back(32 - c);
    }
    point = uncompressed;
    return point;
}

EccPoint setEccPoint_Compressed_Lsb_Y_0() {
    EccPoint point;
    EccPointType type = EccPointType::Compressed_Lsb_Y_0;
    Compressed_Lsb_Y_0 coord;
    for (int c = 0; c < 32; c++) {
        coord.x.push_back(c);
    }
    point = coord;
    return point;
}

EccPoint setEccPoint_X_Coordinate_Only() {
    EccPoint point;
    EccPointType type = EccPointType::X_Coordinate_Only;
    X_Coordinate_Only coord;
    for (int c = 0; c < 32; c++) {
        coord.x.push_back(c);
    }
    point = coord;
    return point;
}

PublicKey setPublicKey_Ecies_Nistp256() {
    EccPoint point = setEccPoint_uncompressed();
    PublicKey key;
    ecies_nistp256 ecies;
    ecies.public_key = point;
    ecies.supported_symm_alg = SymmetricAlgorithm::Aes128_Ccm;
    key = ecies;
    return key;
}

PublicKey setPublicKey_Ecdsa_Nistp256_With_Sha256() {
    EccPoint point = setEccPoint_X_Coordinate_Only();
    PublicKey key;
    ecdsa_nistp256_with_sha256 ecdsa;
    ecdsa.public_key = point;
    key = ecdsa;
    return key;
}

std::list<ItsAidSsp> setSubjectAttribute_Its_Aid_Ssp_List() {
    std::list<ItsAidSsp> itsAidSsp_list;
    for (int c = 0; c < 10; c++) {
        ItsAidSsp itsAidSsp;
        IntX intx;
        intx.set(c + 30);
        itsAidSsp.its_aid = intx;
        for (int c2 = 0; c2 < 10; c2++) {
            itsAidSsp.service_specific_permissions.push_back(c2 + c);
        }
        itsAidSsp_list.push_back(itsAidSsp);
    }
    return itsAidSsp_list;
}

EncryptionKey setSubjectAttribute_Encryption_Key() {
    EccPoint point = setEccPoint_uncompressed();
    EncryptionKey key;
    ecies_nistp256 ecsie;
    ecsie.public_key = point;
    ecsie.supported_symm_alg = SymmetricAlgorithm::Aes128_Ccm;
    key.key = ecsie;
    return key;
}

std::list<IntX> setSubjectAttribute_Its_Aid_List() {
    std::list<IntX> intx_list;
    for (int c = 0; c < 5; c++) {
        IntX intx;
        intx.set(c + 1000);
        intx_list.push_back(intx);
    }
    return intx_list;
}

std::list<ItsAidPriority> setSubjectAttribute_Priority_Its_Aid_List() {
    std::list<ItsAidPriority> itsAidPriority_list;
    for (int c = 0; c < 22; c++) {
        ItsAidPriority itsAidPriority;
        IntX intx;
        intx.set(c + 35);
        itsAidPriority.its_aid = intx;
        itsAidPriority.max_priority = (125 + c);
        itsAidPriority_list.push_back(itsAidPriority);
    }
    return itsAidPriority_list;
}

std::list<ItsAidPrioritySsp> setSubjectAttribute_Priority_Ssp_List() {
    std::list<ItsAidPrioritySsp> ssp_list;
    ItsAidPrioritySsp itsAid;
    IntX intx;
    intx.set(10);
    ByteBuffer buf;
    for (int c = 0; c < 5; c++) {
        buf.push_back(c + 100);
    }
    itsAid.its_aid = intx;
    itsAid.max_priority = 15;
    itsAid.service_specific_permissions = buf;
    ssp_list.push_back(itsAid);

    ByteBuffer buf2;
    intx.set(12);
    for (int c = 0; c < 7; c++) {
        buf2.push_back(c + 200);
    }
    itsAid.its_aid = intx;
    itsAid.max_priority = 125;
    itsAid.service_specific_permissions = buf2;

    ssp_list.push_back(itsAid);
    return ssp_list;
}
