/*
 * Rep4MC.hpp
 *
 */

#ifndef PROTOCOLS_REP4MC_HPP_
#define PROTOCOLS_REP4MC_HPP_

#include "Rep4MC.h"
#include <cstdlib>
#include <cstring>
#include <iostream>

template<class T>
void Rep4MC<T>::exchange(const Player& P)
{
    CODE_LOCATION

    bool malicious = not OnlineOptions::singleton.semi_honest;

    octetStream right, tmp;
    for (auto& secret : this->secrets)
    {
        secret[0].pack(right);
        if (malicious)
            secret[2].pack(tmp);
    }

    if (malicious)
        check_hash.update(tmp);

    const char* mode = std::getenv("SEED_TEST_NATIVE_ATTACK");
    static bool injected = false;
    if (!injected && std::getenv("SEED_TEST_NATIVE_PHASE") && mode &&
        std::strcmp(mode,"opening-wire")==0 && right.get_length()) {
      right.get_data()[0] ^= 1; injected = true;
      std::cerr << "SEED_TEST_ATTACK opening-wire" << std::endl;
    }
    P.pass_around(right, 1);
    this->values.resize(this->secrets.size());
    for (size_t i = 0; i < this->secrets.size(); i++)
    {
        typename T::open_type a, b;
        a.unpack(right);
        this->values[i] = this->secrets[i].sum() + a;
    }

    if (malicious)
        receive_hash.update(right);

    if (OnlineOptions::singleton.has_option("always_check"))
        Check(P);
}

template<class T>
void Rep4MC<T>::Check(const Player& P)
{
    if (check_hash.size == 0)
        return;

    CODE_LOCATION
    octetStream left;
    check_hash.final(left);
    P.pass_around(left, -1);
    octetStream os;
    receive_hash.final(os);
    if (os != left)
        throw mac_fail();
}

#endif /* PROTOCOLS_REP4MC_HPP_ */
