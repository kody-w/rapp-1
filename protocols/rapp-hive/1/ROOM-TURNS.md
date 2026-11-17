# Proposal: room turns for `rapp-hive/1`

- Status: **proposal, not a registration.** Nothing here is ratified. It changes no
  frame, kind, schema, endpoint or anchor revision. For the owner to accept or reject.
- Parent: `rapp-hive/1` (normative text lives at
  `https://github.com/kody-w/rapp-work`, path `protocols/rapp-hive/1/SPEC.md`).
- Proven-winner rule: this starts life as a RAR stack marked `staging`. It moves into
  `rapp-hive/1` only when the owner rules it has won.

## Why

`rapp-hive/1` says who is in a Hive, what a room is and who may read a shared object.
It does not say how several members' Brainstems talk in one room. Every build so far
has had to invent that part, and each invented it differently. Six things were missing
from the protocol text (checked against `rapp-hive/1`, the HIVE-MD draft and the Hive
agent):

| # | Missing today | Where it lives now |
| --- | --- | --- |
| 1 | Several members' Brainstems taking turns from one transcript | nowhere |
| 2 | Speaking to one member or to all | code only, one member only |
| 3 | A Brainstem saying it has nothing to add | nowhere |
| 4 | A private answer shown to others as a marker, not as words | code only, questions only |
| 5 | One question to every member, one page back, with a count | nowhere |
| 6 | A limit on how many calls one message may set off | nowhere |

## Who built this before (free tuition)

- **IRC and Slack:** a channel is one ordered log; a message to one person is the same
  message with a narrower audience. So: one transcript, audience on the turn.
- **Email reply-all storms:** fan-out with no limit takes the system down. So: a stated
  call limit, known before the message is sent.
- **Paxos and Raft:** silence and "no" are different facts. So: a pass is written down;
  a missing answer is reported as missing, never guessed.
- **Matrix:** a redacted event keeps its place in the log. So: a withheld answer keeps
  its place as a marker.

## No new nouns

Every part maps to something `rapp-hive/1` already has.

| This proposal says | Existing noun it is |
| --- | --- |
| room | `rooms[]` entry, section 3.1 |
| turn | one `hive.object` frame, payload `rapp-hive/1-object`, with that room's `room_id` |
| who it is for | the object's `audience` |
| who said it | the object's `producer_rappid` |
| the words | the particle named by `object.hash` |
| what kind of turn | the existing free-text `object.kind` |
| what it answers | the object's `source_frames` |
| order | section 1 rule 6: ascending `utc`, then ascending `frame_hash` |

No new frame kind, payload schema, endpoint, signature format or registry entry type.
The eight kinds of `rapp-hive/1` stay eight.

## The rules (proposed text)

A **room transcript** is every `hive.object` frame in one room whose `object.kind`
begins with `room.`, in section 1 rule 6 order.

1. **Turn.** A turn is one signed `hive.object` frame with `object.kind` set to one of
   `room.turn`, `room.pass`, `room.withheld` or `room.rollup`. A reader **MUST** ignore
   a `room.` value it does not know and keep its place in the order.
2. **One transcript, each from its own side.** A member's Brainstem is given the
   transcript with its own turns as its past words and every other turn as someone
   else's, each labelled with the producer's role. Nothing else **MAY** be added to
   what is sent to `POST /chat`.
3. **Addressing.** `audience` naming every current member of the room means everyone.
   `audience` naming fewer members means those members alone. A Brainstem **MUST NOT**
   be given a turn whose `audience` does not name its member.
4. **Pass.** A Brainstem with nothing to add writes a `room.pass` turn. A pass is a
   fact in the transcript. A reader **MUST NOT** treat a missing turn as a pass.
5. **Private stays private.** If an answer drew on anything its member does not share,
   the words stay with that member. The room is given a `room.withheld` turn in its
   place: same producer, same position, `object.data_class` of `godd`, and no particle
   a non-owner can open. This holds for turns made before another member joined.
6. **Roll-up.** A `room.rollup` turn is one page made from members' answers to one
   question. Its `source_frames` **MUST** list every answer, pass and withheld turn it
   was made from. A reader counts answered members from that list; the page states the
   count as answered of asked. A member with no turn in the list is reported as not yet
   answered. A roll-up **MUST NOT** contain words from a withheld turn.
7. **Call limit.** A room has one whole number, the most Brainstem calls a single
   message may set off. It is known before the message is sent. A producer **MUST**
   stop at the limit and **MUST NOT** write turns past it.
8. **Away.** A member marked away may still be answered for by their Brainstem. Such a
   turn says so in its words. Being away never widens what is shared.

## How to check it

A check passes only on a transcript it can read back. Proposed conformance points:

1. Two members, one room, one message to everyone: each Brainstem's input holds its own
   turns as its own and the other's as someone else's.
2. A turn addressed to one member is absent from every other member's input.
3. A pass is present as `room.pass`; removing it changes the transcript hash.
4. A member answers privately, then a second member joins: the second member's input
   holds zero words of the private answer.
5. A roll-up over M members with K answers reads back as K of M, with the M minus K
   members listed as not yet answered.
6. A message that would set off more calls than the limit stops at the limit.

## What this does not do

- It does not ratify anything, touch the anchor, or change `protocols/index.json`.
- It does not say how fast a member's Brainstem must answer or how it is woken.
- It does not settle a changing roster; that is gap G01 in the Hive gap register.
- Evidence so far is one private build that reported these behaviours working. No
  second independent install has run the six checks above. Until one has, this is a
  staging idea and not a winner.

## One thing found on the way

`rapp-work/1` in this repository depends on `rapp-hive/1`, and `protocols/README.md`
mentions it, but nothing here says where the `rapp-hive/1` text lives. A reader of
this repository alone cannot find it. This file records the place (see Parent above).
Whether `rapp-hive/1` should be listed in this repository's profile index is the
owner's call and is not changed here.
