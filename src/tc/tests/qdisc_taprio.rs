// SPDX-License-Identifier: MIT

use netlink_packet_utils::{Emitable, Parseable};

use crate::{
    tc::{
        TaprioScheduleEntry, TaprioScheduleEntryItem, TaprioTcEntry,
        TcAttribute, TcHandle, TcHeader, TcMessage, TcMessageBuffer, TcOption,
        TcPriomap, TcQdiscTaprioOption,
    },
    AddressFamily,
};

// Capture nlmon of this command:
//
//      tc qdisc replace dev enp86s0 parent root taprio
//         num_tc 3 map 2 2 1 0 2 2 2 2 2 2 2 2 2 2 2 2
//         queues 1@0 1@1 1@2
//         base-time 1000000000
//         sched-entry S 1 300000
//         sched-entry S 3 300000
//         sched-entry S 4 400000
//         flags 0x1
//         txtime-delay 500000
//         clockid CLOCK_TAI
//         fp P E E P P P P P P P P P P P P P
//         max-sdu 0 300 200 0 0 0 0 0 0 0 0 0 0 0 0 0
//         cycle-time 1000000
//         cycle-time-extension 100
//
// Raw packet modification:
//   * rtnetlink header removed.
#[test]
fn test_replace_qdisc_taprio() {
    let raw = vec![
        0x00, // AF_UNSPEC
        0x00, 0x00, 0x00, // padding
        0x02, 0x00, 0x00, 0x00, // iface index: 2
        0x00, 0x00, 0x00, 0x00, // handle 0:0 (TC_H_UNSPEC)
        0xff, 0xff, 0xff, 0xff, // parent u32::MAX (TC_H_ROOT)
        0x00, 0x00, 0x00, 0x00, // info: 0
        0x0b, 0x00, // length 11
        0x01, 0x00, // TCA_KIND
        0x74, 0x61, 0x70, 0x72, // "taprio\0" and 1 bytes pad
        0x69, 0x6f, 0x00, 0x00, // ...
        0xb0, 0x02, // length 688
        0x02, 0x00, // TCA_OPTIONS for `taprio`
        0x08, 0x00, // length 8
        0x05, 0x00, // TCA_TAPRIO_ATTR_SCHED_CLOCKID
        0x0b, 0x00, 0x00, 0x00, // CLOCK_TAI (11)
        0x08, 0x00, // length 8
        0x0a, 0x00, // TCA_TAPRIO_ATTR_FLAGS
        0x01, 0x00, 0x00, 0x00, // 0x1 (tx-time assist feature)
        0x56, 0x00, // length 86
        0x01, 0x00, // TCA_TAPRIO_ATTR_PRIOMAP (struct tc_mqprio_qopt)
        0x03, // num_tc (3)
        0x02, 0x02, 0x01, 0x00, // prio tc map (16 bytes)
        0x02, 0x02, 0x02, 0x02, // ...
        0x02, 0x02, 0x02, 0x02, // ...
        0x02, 0x02, 0x02, 0x02, // ...
        0x00, // hw (0)
        0x01, 0x00, 0x01, 0x00, // count (16x u16)
        0x01, 0x00, 0x00, 0x00, // ...
        0x00, 0x00, 0x00, 0x00, // ...
        0x00, 0x00, 0x00, 0x00, // ...
        0x00, 0x00, 0x00, 0x00, // ...
        0x00, 0x00, 0x00, 0x00, // ...
        0x00, 0x00, 0x00, 0x00, // ...
        0x00, 0x00, 0x00, 0x00, // ...
        0x00, 0x00, 0x01, 0x00, // offset (16x u16)
        0x02, 0x00, 0x00, 0x00, // ...
        0x00, 0x00, 0x00, 0x00, // ...
        0x00, 0x00, 0x00, 0x00, // ...
        0x00, 0x00, 0x00, 0x00, // ...
        0x00, 0x00, 0x00, 0x00, // ...
        0x00, 0x00, 0x00, 0x00, // ...
        0x00, 0x00, 0x00, 0x00, // ...
        0x00, 0x00, // padding
        0x08, 0x00, // length 8
        0x0b, 0x00, // TCA_TAPRIO_ATTR_TXTIME_DELAY
        0x20, 0xa1, 0x07, 0x00, // tx-time delay 500000
        0x0c, 0x00, // length 12
        0x03, 0x00, // TCA_TAPRIO_ATTR_SCHED_BASE_TIME
        0x00, 0xca, 0x9a, 0x3b, // basetime 1000000000
        0x00, 0x00, 0x00, 0x00, // ...
        0x0c, 0x00, // length 12
        0x08, 0x00, // TCA_TAPRIO_ATTR_SCHED_CYCLE_TIME
        0x40, 0x42, 0x0f, 0x00, // cycletime 1000000
        0x00, 0x00, 0x00, 0x00, // ...
        0x0c, 0x00, // length 12
        0x09, 0x00, // TCA_TAPRIO_ATTR_SCHED_CYCLE_TIME_EXTENSION
        0x64, 0x00, 0x00, 0x00, // cycletime extension 100
        0x00, 0x00, 0x00, 0x00, // ...
        0x1c, 0x00, // length 28
        0x0c, 0x80, // TCA_TAPRIO_ATTR_TC_ENTRY | NLA_F_NESTED
        0x08, 0x00, // length 8
        0x01, 0x00, // TCA_TAPRIO_TC_ENTRY_INDEX
        0x00, 0x00, 0x00, 0x00, // index 0
        0x08, 0x00, // length 8
        0x02, 0x00, // TCA_TAPRIO_TC_ENTRY_MAX_SDU
        0x00, 0x00, 0x00, 0x00, // max_sdu 0
        0x08, 0x00, // length 8
        0x03, 0x00, // TCA_TAPRIO_TC_ENTRY_FP
        0x02, 0x00, 0x00, 0x00, // fp 2
        0x1c, 0x00, // length 28
        0x0c, 0x80, // TCA_TAPRIO_ATTR_TC_ENTRY | NLA_F_NESTED
        0x08, 0x00, // length 8
        0x01, 0x00, // TCA_TAPRIO_TC_ENTRY_INDEX
        0x01, 0x00, 0x00, 0x00, // index 1
        0x08, 0x00, // length 8
        0x02, 0x00, // TCA_TAPRIO_TC_ENTRY_MAX_SDU
        0x2c, 0x01, 0x00, 0x00, // max_sdu 300
        0x08, 0x00, // length 8
        0x03, 0x00, // TCA_TAPRIO_TC_ENTRY_FP
        0x01, 0x00, 0x00, 0x00, // fp 1
        0x1c, 0x00, // length 28
        0x0c, 0x80, // TCA_TAPRIO_ATTR_TC_ENTRY | NLA_F_NESTED
        0x08, 0x00, // length 8
        0x01, 0x00, // TCA_TAPRIO_TC_ENTRY_INDEX
        0x02, 0x00, 0x00, 0x00, // index 2
        0x08, 0x00, // length 8
        0x02, 0x00, // TCA_TAPRIO_TC_ENTRY_MAX_SDU
        0xc8, 0x00, 0x00, 0x00, // max_sdu 300
        0x08, 0x00, // length 8
        0x03, 0x00, // TCA_TAPRIO_TC_ENTRY_FP
        0x01, 0x00, 0x00, 0x00, // fp 1
        0x1c, 0x00, // length 28
        0x0c, 0x80, // TCA_TAPRIO_ATTR_TC_ENTRY | NLA_F_NESTED
        0x08, 0x00, // length 8
        0x01, 0x00, // TCA_TAPRIO_TC_ENTRY_INDEX
        0x03, 0x00, 0x00, 0x00, // index 3
        0x08, 0x00, // length 8
        0x02, 0x00, // TCA_TAPRIO_TC_ENTRY_MAX_SDU
        0x00, 0x00, 0x00, 0x00, // max_sdu 0
        0x08, 0x00, // length 8
        0x03, 0x00, // TCA_TAPRIO_TC_ENTRY_FP
        0x02, 0x00, 0x00, 0x00, // fp 2
        0x1c, 0x00, // length 28
        0x0c, 0x80, // TCA_TAPRIO_ATTR_TC_ENTRY | NLA_F_NESTED
        0x08, 0x00, // length 8
        0x01, 0x00, // TCA_TAPRIO_TC_ENTRY_INDEX
        0x04, 0x00, 0x00, 0x00, // index 4
        0x08, 0x00, // length 8
        0x02, 0x00, // TCA_TAPRIO_TC_ENTRY_MAX_SDU
        0x00, 0x00, 0x00, 0x00, // max_sdu 0
        0x08, 0x00, // length 8
        0x03, 0x00, // TCA_TAPRIO_TC_ENTRY_FP
        0x02, 0x00, 0x00, 0x00, // fp 2
        0x1c, 0x00, // length 28
        0x0c, 0x80, // TCA_TAPRIO_ATTR_TC_ENTRY | NLA_F_NESTED
        0x08, 0x00, // length 8
        0x01, 0x00, // TCA_TAPRIO_TC_ENTRY_INDEX
        0x05, 0x00, 0x00, 0x00, // index 5
        0x08, 0x00, // length 8
        0x02, 0x00, // TCA_TAPRIO_TC_ENTRY_MAX_SDU
        0x00, 0x00, 0x00, 0x00, // max_sdu 0
        0x08, 0x00, // length 8
        0x03, 0x00, // TCA_TAPRIO_TC_ENTRY_FP
        0x02, 0x00, 0x00, 0x00, // fp 2
        0x1c, 0x00, // length 28
        0x0c, 0x80, // TCA_TAPRIO_ATTR_TC_ENTRY | NLA_F_NESTED
        0x08, 0x00, // length 8
        0x01, 0x00, // TCA_TAPRIO_TC_ENTRY_INDEX
        0x06, 0x00, 0x00, 0x00, // index 6
        0x08, 0x00, // length 8
        0x02, 0x00, // TCA_TAPRIO_TC_ENTRY_MAX_SDU
        0x00, 0x00, 0x00, 0x00, // max_sdu 0
        0x08, 0x00, // length 8
        0x03, 0x00, // TCA_TAPRIO_TC_ENTRY_FP
        0x02, 0x00, 0x00, 0x00, // fp 2
        0x1c, 0x00, // length 28
        0x0c, 0x80, // TCA_TAPRIO_ATTR_TC_ENTRY | NLA_F_NESTED
        0x08, 0x00, // length 8
        0x01, 0x00, // TCA_TAPRIO_TC_ENTRY_INDEX
        0x07, 0x00, 0x00, 0x00, // index 7
        0x08, 0x00, // length 8
        0x02, 0x00, // TCA_TAPRIO_TC_ENTRY_MAX_SDU
        0x00, 0x00, 0x00, 0x00, // max_sdu 0
        0x08, 0x00, // length 8
        0x03, 0x00, // TCA_TAPRIO_TC_ENTRY_FP
        0x02, 0x00, 0x00, 0x00, // fp 2
        0x1c, 0x00, // length 28
        0x0c, 0x80, // TCA_TAPRIO_ATTR_TC_ENTRY | NLA_F_NESTED
        0x08, 0x00, // length 8
        0x01, 0x00, // TCA_TAPRIO_TC_ENTRY_INDEX
        0x08, 0x00, 0x00, 0x00, // index 8
        0x08, 0x00, // length 8
        0x02, 0x00, // TCA_TAPRIO_TC_ENTRY_MAX_SDU
        0x00, 0x00, 0x00, 0x00, // max_sdu 0
        0x08, 0x00, // length 8
        0x03, 0x00, // TCA_TAPRIO_TC_ENTRY_FP
        0x02, 0x00, 0x00, 0x00, // fp 2
        0x1c, 0x00, // length 28
        0x0c, 0x80, // TCA_TAPRIO_ATTR_TC_ENTRY | NLA_F_NESTED
        0x08, 0x00, // length 8
        0x01, 0x00, // TCA_TAPRIO_TC_ENTRY_INDEX
        0x09, 0x00, 0x00, 0x00, // index 9
        0x08, 0x00, // length 8
        0x02, 0x00, // TCA_TAPRIO_TC_ENTRY_MAX_SDU
        0x00, 0x00, 0x00, 0x00, // max_sdu 0
        0x08, 0x00, // length 8
        0x03, 0x00, // TCA_TAPRIO_TC_ENTRY_FP
        0x02, 0x00, 0x00, 0x00, // fp 2
        0x1c, 0x00, // length 28
        0x0c, 0x80, // TCA_TAPRIO_ATTR_TC_ENTRY | NLA_F_NESTED
        0x08, 0x00, // length 8
        0x01, 0x00, // TCA_TAPRIO_TC_ENTRY_INDEX
        0x0a, 0x00, 0x00, 0x00, // index 10
        0x08, 0x00, // length 8
        0x02, 0x00, // TCA_TAPRIO_TC_ENTRY_MAX_SDU
        0x00, 0x00, 0x00, 0x00, // max_sdu 0
        0x08, 0x00, // length 8
        0x03, 0x00, // TCA_TAPRIO_TC_ENTRY_FP
        0x02, 0x00, 0x00, 0x00, // fp 2
        0x1c, 0x00, // length 28
        0x0c, 0x80, // TCA_TAPRIO_ATTR_TC_ENTRY | NLA_F_NESTED
        0x08, 0x00, // length 8
        0x01, 0x00, // TCA_TAPRIO_TC_ENTRY_INDEX
        0x0b, 0x00, 0x00, 0x00, // index 11
        0x08, 0x00, // length 8
        0x02, 0x00, // TCA_TAPRIO_TC_ENTRY_MAX_SDU
        0x00, 0x00, 0x00, 0x00, // max_sdu 0
        0x08, 0x00, // length 8
        0x03, 0x00, // TCA_TAPRIO_TC_ENTRY_FP
        0x02, 0x00, 0x00, 0x00, // fp 2
        0x1c, 0x00, // length 28
        0x0c, 0x80, // TCA_TAPRIO_ATTR_TC_ENTRY | NLA_F_NESTED
        0x08, 0x00, // length 8
        0x01, 0x00, // TCA_TAPRIO_TC_ENTRY_INDEX
        0x0c, 0x00, 0x00, 0x00, // index 12
        0x08, 0x00, // length 8
        0x02, 0x00, // TCA_TAPRIO_TC_ENTRY_MAX_SDU
        0x00, 0x00, 0x00, 0x00, // max_sdu 0
        0x08, 0x00, // length 8
        0x03, 0x00, // TCA_TAPRIO_TC_ENTRY_FP
        0x02, 0x00, 0x00, 0x00, // fp 2
        0x1c, 0x00, // length 28
        0x0c, 0x80, // TCA_TAPRIO_ATTR_TC_ENTRY | NLA_F_NESTED
        0x08, 0x00, // length 8
        0x01, 0x00, // TCA_TAPRIO_TC_ENTRY_INDEX
        0x0d, 0x00, 0x00, 0x00, // index 13
        0x08, 0x00, // length 8
        0x02, 0x00, // TCA_TAPRIO_TC_ENTRY_MAX_SDU
        0x00, 0x00, 0x00, 0x00, // max_sdu 0
        0x08, 0x00, // length 8
        0x03, 0x00, // TCA_TAPRIO_TC_ENTRY_FP
        0x02, 0x00, 0x00, 0x00, // fp 2
        0x1c, 0x00, // length 28
        0x0c, 0x80, // TCA_TAPRIO_ATTR_TC_ENTRY | NLA_F_NESTED
        0x08, 0x00, // length 8
        0x01, 0x00, // TCA_TAPRIO_TC_ENTRY_INDEX
        0x0e, 0x00, 0x00, 0x00, // index 14
        0x08, 0x00, // length 8
        0x02, 0x00, // TCA_TAPRIO_TC_ENTRY_MAX_SDU
        0x00, 0x00, 0x00, 0x00, // max_sdu 0
        0x08, 0x00, // length 8
        0x03, 0x00, // TCA_TAPRIO_TC_ENTRY_FP
        0x02, 0x00, 0x00, 0x00, // fp 2
        0x1c, 0x00, // length 28
        0x0c, 0x80, // TCA_TAPRIO_ATTR_TC_ENTRY | NLA_F_NESTED
        0x08, 0x00, // length 8
        0x01, 0x00, // TCA_TAPRIO_TC_ENTRY_INDEX
        0x0f, 0x00, 0x00, 0x00, // index 15
        0x08, 0x00, // length 8
        0x02, 0x00, // TCA_TAPRIO_TC_ENTRY_MAX_SDU
        0x00, 0x00, 0x00, 0x00, // max_sdu 0
        0x08, 0x00, // length 8
        0x03, 0x00, // TCA_TAPRIO_TC_ENTRY_FP
        0x02, 0x00, 0x00, 0x00, // fp 2
        0x58, 0x00, // length 88
        0x02, 0x80, // TCA_TAPRIO_ATTR_SCHED_ENTRY_LIST | NLA_F_NESTED
        0x1c, 0x00, // length 28
        0x01, 0x00, // TCA_TAPRIO_SCHED_ENTRY
        0x05, 0x00, // length 5
        0x02, 0x00, // TCA_TAPRIO_SCHED_ENTRY_CMD
        0x00, // TC_TAPRIO_CMD_SET_GATES (S)
        0x00, 0x00, 0x00, // padding
        0x08, 0x00, // length 8
        0x03, 0x00, // TCA_TAPRIO_SCHED_ENTRY_GATE_MASK
        0x01, 0x00, 0x00, 0x00, // gate mask 1
        0x08, 0x00, // length 8
        0x04, 0x00, // TCA_TAPRIO_SCHED_ENTRY_INTERVAL
        0xe0, 0x93, 0x04, 0x00, // interval 300000
        0x1c, 0x00, // length 28
        0x01, 0x00, // TCA_TAPRIO_SCHED_ENTRY
        0x05, 0x00, // length 5
        0x02, 0x00, // TCA_TAPRIO_SCHED_ENTRY_CMD
        0x00, // TC_TAPRIO_CMD_SET_GATES (S)
        0x00, 0x00, 0x00, // padding
        0x08, 0x00, // length 8
        0x03, 0x00, // TCA_TAPRIO_SCHED_ENTRY_GATE_MASK
        0x03, 0x00, 0x00, 0x00, // gate mask 3
        0x08, 0x00, // length 8
        0x04, 0x00, // TCA_TAPRIO_SCHED_ENTRY_INTERVAL
        0xe0, 0x93, 0x04, 0x00, // interval 300000
        0x1c, 0x00, // length 28
        0x01, 0x00, // TCA_TAPRIO_SCHED_ENTRY
        0x05, 0x00, // length 5
        0x02, 0x00, // TCA_TAPRIO_SCHED_ENTRY_CMD
        0x00, // TC_TAPRIO_CMD_SET_GATES (S)
        0x00, 0x00, 0x00, // padding
        0x08, 0x00, // length 8
        0x03, 0x00, // TCA_TAPRIO_SCHED_ENTRY_GATE_MASK
        0x04, 0x00, 0x00, 0x00, // gate mask 4
        0x08, 0x00, // length 8
        0x04, 0x00, // TCA_TAPRIO_SCHED_ENTRY_INTERVAL
        0x80, 0x1a, 0x06, 0x00, // interval 400000
    ];

    let expected = TcMessage {
        header: TcHeader {
            family: AddressFamily::Unspec,
            index: 2,
            handle: TcHandle::UNSPEC,
            parent: TcHandle::ROOT,
            info: 0,
        },
        attributes: vec![
            TcAttribute::Kind("taprio".to_string()),
            TcAttribute::Options(vec![
                TcOption::Taprio(TcQdiscTaprioOption::ClockId(11)),
                TcOption::Taprio(TcQdiscTaprioOption::Flags(0x1)),
                TcOption::Taprio(TcQdiscTaprioOption::Priomap(TcPriomap {
                    num_tc: 3,
                    prio_tc_map: [
                        2, 2, 1, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                    ],
                    hw: 0,
                    count: [1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    offset: [0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                })),
                TcOption::Taprio(TcQdiscTaprioOption::TxtimeDelay(500000)),
                TcOption::Taprio(TcQdiscTaprioOption::Basetime(1000000000)),
                TcOption::Taprio(TcQdiscTaprioOption::Cycletime(1000000)),
                TcOption::Taprio(TcQdiscTaprioOption::CycletimeExtension(100)),
                TcOption::Taprio(TcQdiscTaprioOption::Tc(vec![
                    TaprioTcEntry::Index(0),
                    TaprioTcEntry::MaxSdu(0),
                    TaprioTcEntry::fp_from_char('P').unwrap(),
                ])),
                TcOption::Taprio(TcQdiscTaprioOption::Tc(vec![
                    TaprioTcEntry::Index(1),
                    TaprioTcEntry::MaxSdu(300),
                    TaprioTcEntry::fp_from_char('E').unwrap(),
                ])),
                TcOption::Taprio(TcQdiscTaprioOption::Tc(vec![
                    TaprioTcEntry::Index(2),
                    TaprioTcEntry::MaxSdu(200),
                    TaprioTcEntry::fp_from_char('E').unwrap(),
                ])),
                TcOption::Taprio(TcQdiscTaprioOption::Tc(vec![
                    TaprioTcEntry::Index(3),
                    TaprioTcEntry::MaxSdu(0),
                    TaprioTcEntry::fp_from_char('P').unwrap(),
                ])),
                TcOption::Taprio(TcQdiscTaprioOption::Tc(vec![
                    TaprioTcEntry::Index(4),
                    TaprioTcEntry::MaxSdu(0),
                    TaprioTcEntry::fp_from_char('P').unwrap(),
                ])),
                TcOption::Taprio(TcQdiscTaprioOption::Tc(vec![
                    TaprioTcEntry::Index(5),
                    TaprioTcEntry::MaxSdu(0),
                    TaprioTcEntry::fp_from_char('P').unwrap(),
                ])),
                TcOption::Taprio(TcQdiscTaprioOption::Tc(vec![
                    TaprioTcEntry::Index(6),
                    TaprioTcEntry::MaxSdu(0),
                    TaprioTcEntry::fp_from_char('P').unwrap(),
                ])),
                TcOption::Taprio(TcQdiscTaprioOption::Tc(vec![
                    TaprioTcEntry::Index(7),
                    TaprioTcEntry::MaxSdu(0),
                    TaprioTcEntry::fp_from_char('P').unwrap(),
                ])),
                TcOption::Taprio(TcQdiscTaprioOption::Tc(vec![
                    TaprioTcEntry::Index(8),
                    TaprioTcEntry::MaxSdu(0),
                    TaprioTcEntry::fp_from_char('P').unwrap(),
                ])),
                TcOption::Taprio(TcQdiscTaprioOption::Tc(vec![
                    TaprioTcEntry::Index(9),
                    TaprioTcEntry::MaxSdu(0),
                    TaprioTcEntry::fp_from_char('P').unwrap(),
                ])),
                TcOption::Taprio(TcQdiscTaprioOption::Tc(vec![
                    TaprioTcEntry::Index(10),
                    TaprioTcEntry::MaxSdu(0),
                    TaprioTcEntry::fp_from_char('P').unwrap(),
                ])),
                TcOption::Taprio(TcQdiscTaprioOption::Tc(vec![
                    TaprioTcEntry::Index(11),
                    TaprioTcEntry::MaxSdu(0),
                    TaprioTcEntry::fp_from_char('P').unwrap(),
                ])),
                TcOption::Taprio(TcQdiscTaprioOption::Tc(vec![
                    TaprioTcEntry::Index(12),
                    TaprioTcEntry::MaxSdu(0),
                    TaprioTcEntry::fp_from_char('P').unwrap(),
                ])),
                TcOption::Taprio(TcQdiscTaprioOption::Tc(vec![
                    TaprioTcEntry::Index(13),
                    TaprioTcEntry::MaxSdu(0),
                    TaprioTcEntry::fp_from_char('P').unwrap(),
                ])),
                TcOption::Taprio(TcQdiscTaprioOption::Tc(vec![
                    TaprioTcEntry::Index(14),
                    TaprioTcEntry::MaxSdu(0),
                    TaprioTcEntry::fp_from_char('P').unwrap(),
                ])),
                TcOption::Taprio(TcQdiscTaprioOption::Tc(vec![
                    TaprioTcEntry::Index(15),
                    TaprioTcEntry::MaxSdu(0),
                    TaprioTcEntry::fp_from_char('P').unwrap(),
                ])),
                TcOption::Taprio(TcQdiscTaprioOption::Schedule(vec![
                    TaprioScheduleEntry::Entry(vec![
                        TaprioScheduleEntryItem::cmd_from_char('S').unwrap(),
                        TaprioScheduleEntryItem::GateMask(0x1),
                        TaprioScheduleEntryItem::Interval(300000),
                    ]),
                    TaprioScheduleEntry::Entry(vec![
                        TaprioScheduleEntryItem::cmd_from_char('S').unwrap(),
                        TaprioScheduleEntryItem::GateMask(0x3),
                        TaprioScheduleEntryItem::Interval(300000),
                    ]),
                    TaprioScheduleEntry::Entry(vec![
                        TaprioScheduleEntryItem::cmd_from_char('S').unwrap(),
                        TaprioScheduleEntryItem::GateMask(0x4),
                        TaprioScheduleEntryItem::Interval(400000),
                    ]),
                ])),
            ]),
        ],
    };

    assert_eq!(
        expected,
        TcMessage::parse(&TcMessageBuffer::new(&raw)).unwrap()
    );

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}
