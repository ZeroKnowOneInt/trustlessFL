/*
 * Rep4Secret.cpp
 *
 */

#ifndef GC_REP4SECRET_CPP_
#define GC_REP4SECRET_CPP_

#include "Rep4Secret.h"

#include "ShareSecret.hpp"
#include "ShareThread.hpp"
#include "Protocols/Rep4MC.hpp"
#include "Protocols/Rep4.hpp"
#include "Protocols/Rep4Input.hpp"

namespace GC
{

void Rep4Secret::load_clear(int n, const Integer& x)
{
    this->check_length(n, x);
    *this = constant(x, ShareThread<This>::s().P->my_num());
}


void Rep4Secret::inputb(Processor<Rep4Secret>& processor, const ArgVector& args)
{
    inputb(processor, processor, args);
}

void Rep4Secret::inputb(Processor<Rep4Secret>& processor,
        ProcessorBase& input_processor, const ArgVector& args)
{
    if (args.empty() or args.size() % 4 != 0)
        throw runtime_error("invalid native component import arguments");
    bool importing = false;
    for (auto x : InputArgList(args))
        importing |= x.from == 4;
    if (not importing)
    {
        ShareSecret<Rep4Secret>::inputb(processor, input_processor, args);
        return;
    }
    auto& party = ShareThread<Rep4Secret>::s();
    auto& P = *party.P;
    if (P.num_players() != 4 or OnlineOptions::singleton.semi_honest
            or BaseMachine::thread_num != 0)
        throw runtime_error("native component import requires active main-thread Rep4");
    size_t count = args.size() / 4;
    unsigned int width = args.at(1);
    if (count == 0 or count > 512 or (width != 16 and width != 32))
        throw runtime_error("invalid native component import shape");
    for (auto x : InputArgList(args))
        if (x.from != 4 or x.n_bits != width or x.n_shift != 0)
            throw runtime_error("mixed native component import arguments");
    static thread_local uint64_t sequence = 0;
    if (sequence == UINT64_MAX)
        throw runtime_error("native component import counter exhausted");
    uint64_t current = sequence++;
    int me = P.my_num();
    vector<Rep4Secret> pending(count);
    array<octetStream, 4> digests;
    bool bad = false;
    // FIFO order: absolute component ascending, then coordinates in the chunk.
    for (int component = 0; component < 4; component++)
    {
        if (component == me)
            continue;
        Hash hash;
        hash.update(string("trustlessfl/rep4-native-component/v1"));
        octetStream domain;
        domain.store_int<8>(current);
        domain.store_int<4>(width);
        domain.store_int<4>(count);
        domain.store_int<1>(component);
        hash.update(domain);
        octetStream values;
        size_t k = 0;
        for (size_t index = 0; index < count; index++)
        {
            auto value = input_processor.get_input<IntInput<bigint>>(false, 0).items[0];
            bool canonical = value >= 0 and value < (bigint(1) << width);
            bad |= not canonical;
            BitVec word(canonical ? value.get_si() : 0);
            pending[k++][P.get_offset(component) - 1] = word;
            word.pack(values, width);
        }
        hash.update(values);
        hash.final(digests[component]);
    }
    // Component digests go only to its other two holders, never its outsider.
    octetStreams sends(P), received;
    for (int peer = 0; peer < 4; peer++)
        if (peer != me)
            for (int component = 0; component < 4; component++)
                if (component != me and component != peer)
                    sends[peer].concat(digests[component]);
    P.send_receive_all(sends, received);
    for (int peer = 0; peer < 4; peer++)
    {
        if (peer == me)
            continue;
        if (received[peer].get_length() != 2 * Hash::hash_length)
        {
            bad = true;
            continue;
        }
        for (int component = 0; component < 4; component++)
            if (component != me and component != peer)
            {
                octetStream other;
                received[peer].consume(other, Hash::hash_length);
                bad |= other != digests[component];
            }
    }
    // All honest parties decide before committing any share to registers.
    // Verify broadcast NOW, not at a later aggregate opening/checkpoint.
    octetStreams statuses(P);
    statuses[me].store_int<8>(current);
    statuses[me].store_int<4>(count);
    statuses[me].store_int<4>(width);
    statuses[me].store_int<1>(bad ? 1 : 0);
    P.Broadcast_Receive(statuses);
    P.Check_Broadcast();
    for (auto& status : statuses)
    {
        if (status.get_length() != 17)
        {
            bad = true;
            continue;
        }
        auto peer_sequence = status.get_int<8>();
        auto peer_count = status.get_int<4>();
        auto peer_width = status.get_int<4>();
        auto peer_bad = status.get_int<1>();
        bad |= peer_sequence != current or peer_count != count
                or peer_width != width or peer_bad != 0;
    }
    if (bad)
        throw runtime_error("inconsistent native mask components");
    size_t k = 0;
    for (auto x : InputArgList(args))
        processor.S[x.dest] = pending[k++];
}

}

#endif /* GC_REP4SECRET_CPP_ */
