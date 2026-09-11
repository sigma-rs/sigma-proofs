//! Constant-time selection, swap, and oblivious compaction machinery.

use alloc::vec::Vec;
use itertools::Itertools;
use subtle::{Choice, ConditionallySelectable};

/// Elementwise constant-time selection over two equal-length slices.
pub(super) fn select_each<T>(
    a: &[T],
    b: &[T],
    choice: Choice,
    select: fn(&T, &T, Choice) -> T,
) -> Vec<T> {
    a.iter()
        .zip_eq(b)
        .map(|(a, b)| select(a, b, choice))
        .collect()
}

pub(super) fn count_choices(choices: &[Choice]) -> usize {
    let mut sum: u32 = 0;
    for choice in choices {
        let inc = sum.wrapping_add(1);
        sum = u32::conditional_select(&sum, &inc, *choice);
    }
    sum as usize
}

#[derive(Clone, Copy)]
pub(super) struct Evaluation<T> {
    pub(super) x: T,
    pub(super) y: T,
}

impl<T: ConditionallySelectable> ConditionallySelectable for Evaluation<T> {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Evaluation {
            x: T::conditional_select(&a.x, &b.x, choice),
            y: T::conditional_select(&a.y, &b.y, choice),
        }
    }
}

// The three functions below are the oblivious compaction kernel. Every index
// is fixed by the recursion — `n` is halved down from a power of two and the
// loop counters run to those halves — so none of them can depend on a witness
// or on anything off the wire. They index rather than look up fallibly on
// purpose: an `Option` here is a branch, and a branch on a secret-dependent
// path is the one thing this module exists to avoid. The bounds are checked
// instead by the `debug_assert!`s below and by the Kani harnesses.
#[allow(clippy::indexing_slicing)]
fn conditional_swap_point<T: ConditionallySelectable>(
    points: &mut [T],
    left: usize,
    right: usize,
    swap: Choice,
) {
    // The obliviousness proof compares this sequence between mark patterns.
    #[cfg(kani)]
    verification::trace::record(left, right);

    if left == right {
        return;
    }
    if left < right {
        let (head, tail) = points.split_at_mut(right);
        T::conditional_swap(&mut head[left], &mut tail[0], swap);
    } else {
        let (head, tail) = points.split_at_mut(left);
        T::conditional_swap(&mut tail[0], &mut head[right], swap);
    }
}

#[allow(clippy::indexing_slicing)]
fn oroffcompact_points<T: ConditionallySelectable>(
    points: &mut [T],
    marks: &[Choice],
    offset: usize,
) {
    let n = points.len();
    if n <= 1 {
        return;
    }
    debug_assert_eq!(n, marks.len());
    debug_assert!(n.is_power_of_two());

    let half = n / 2;
    let mut m = 0usize;
    for mark in &marks[..half] {
        m += mark.unwrap_u8() as usize;
    }

    if n == 2 {
        let z = Choice::from((offset & 1) as u8);
        let b = ((!marks[0]) & marks[1]) ^ z;
        conditional_swap_point(points, 0, 1, b);
        return;
    }

    // `half` is a power of two, so both reductions are masks. Spelled `%` the
    // compiler cannot see that and may reach for the hardware divider, whose
    // latency is operand-dependent on some targets — and `m` counts marks.
    let offset_mod = offset & (half - 1);
    oroffcompact_points(&mut points[..half], &marks[..half], offset_mod);
    let offset_plus_m_mod = (offset + m) & (half - 1);
    oroffcompact_points(&mut points[half..], &marks[half..], offset_plus_m_mod);

    let s = Choice::from(((offset_mod + m) >= half) as u8) ^ Choice::from((offset >= half) as u8);
    for i in 0..half {
        let b = s ^ Choice::from((i >= offset_plus_m_mod) as u8);
        conditional_swap_point(points, i, i + half, b);
    }
}

/// Moves the marked entries of `points` to the front obliviously.
#[allow(clippy::indexing_slicing)]
pub(super) fn oblivious_compact_points<T: ConditionallySelectable>(
    points: &mut [T],
    marks: &[Choice],
) {
    let n = points.len();
    if n == 0 {
        return;
    }
    debug_assert_eq!(n, marks.len());

    let n1 = 1usize << (usize::BITS as usize - 1 - n.leading_zeros() as usize);
    let n2 = n - n1;
    let mut m = 0usize;
    for mark in &marks[..n2] {
        m += mark.unwrap_u8() as usize;
    }

    if n2 > 0 {
        oblivious_compact_points(&mut points[..n2], &marks[..n2]);
    }
    // `n1` is a power of two by construction; mask rather than divide, as above.
    oroffcompact_points(&mut points[n2..], &marks[n2..], (n1 - n2 + m) & (n1 - 1));

    for i in 0..n2 {
        let b = Choice::from((i >= m) as u8);
        conditional_swap_point(points, i, i + n1, b);
    }
}

/// Chooses which branches a threshold prover simulates.
///
/// Exactly `valid.len() - threshold` flags come back set, for every validity
/// pattern — including the unprovable one, where fewer than `threshold`
/// witnesses are valid and some branch the prover cannot satisfy is run as
/// real anyway. That count is the number of challenges the wire format
/// carries, so a validity pattern that moved it would put the size of the
/// prover's witness set into the transcript. `simulator_flag_count_is_fixed`
/// pins it for every pattern; the `debug_assert` in `prover_response_threshold`
/// that used to be the only check of it is compiled out of release.
pub(super) fn simulator_flags(valid: &[Choice], threshold: usize) -> Vec<Choice> {
    let valid_count = count_choices(valid);
    let provable = Choice::from((valid_count >= threshold) as u8);
    let valid_count = valid_count as u32;
    let threshold = threshold as u32;

    // Provable: seed the surplus `valid_count - threshold` valid branches into
    // the simulated set. Unprovable: fill the deficit back out of the invalid
    // ones. `provable` decides which counter is live; the other stays zero.
    let mut remaining_seeds =
        u32::conditional_select(&0, &valid_count.wrapping_sub(threshold), provable);
    let mut remaining_fills =
        u32::conditional_select(&threshold.wrapping_sub(valid_count), &0, provable);

    let mut flags = Vec::with_capacity(valid.len());
    for &valid_witness in valid {
        let should_seed = valid_witness & Choice::from((remaining_seeds != 0) as u8);
        remaining_seeds = remaining_seeds.wrapping_sub(should_seed.unwrap_u8() as u32);
        flags.push((!valid_witness) | should_seed);
    }
    for (flag, &valid_witness) in flags.iter_mut().zip_eq(valid) {
        let fill_real = (!valid_witness) & Choice::from((remaining_fills != 0) as u8);
        remaining_fills = remaining_fills.wrapping_sub(fill_real.unwrap_u8() as u32);
        *flag &= !fill_real;
    }
    flags
}

/// Machine-checked proofs of the compaction contract.
///
/// These run under [Kani](https://model-checking.github.io/kani), which
/// explores *every* mark pattern up to the bound rather than sampling them:
///
///     cargo kani
///
/// Bounded model checking is the right tool here precisely because the state
/// space is finite and small. The interesting variable is the mark pattern —
/// `2^n` of them — and the index arithmetic in `oroffcompact_points` (the
/// `offset + m` rotations, the `n1`/`n2` split for non-power-of-two lengths)
/// is where an off-by-one would hide. Tests sample that space; this covers it.
///
/// Three claims are proved, and they are not substitutes for one another:
///
/// - **correctness**, that compaction is the permutation the caller expects;
/// - **obliviousness**, that the marks never steer a memory access, which is
///   the reason this module exists at all;
/// - **shape**, that a threshold prover simulates exactly `n - t` branches
///   whatever it holds, so the transcript's size says nothing about how many
///   witnesses it has.
///
/// Only the first was ever a completeness property. The other two are the
/// ones the threat model leans on.
///
/// Obliviousness here binds what this source does, not what LLVM emits from
/// it: a `Choice` select lowered back into a branch is out of reach at this
/// level and stays the job of `tests/dudect.rs`. What it does catch is the
/// regression a person introduces — an early return keyed on the marks.
#[cfg(kani)]
mod verification {
    use super::{count_choices, oblivious_compact_points, simulator_flags, Evaluation};
    use alloc::vec::Vec;
    use subtle::Choice;

    /// Records the index pairs `conditional_swap_point` visits, so a proof can
    /// compare the access sequence between two mark patterns. Kani harnesses
    /// are single-threaded, which is what makes the global sound here.
    pub(super) mod trace {
        use alloc::vec::Vec;

        static mut TRACE: Vec<(usize, usize)> = Vec::new();

        #[allow(unsafe_code)]
        fn with<R>(f: impl FnOnce(&mut Vec<(usize, usize)>) -> R) -> R {
            unsafe { f(&mut *core::ptr::addr_of_mut!(TRACE)) }
        }

        pub(in super::super) fn record(left: usize, right: usize) {
            with(|trace| trace.push((left, right)));
        }

        pub(super) fn take() -> Vec<(usize, usize)> {
            with(core::mem::take)
        }
    }

    fn choices<const N: usize>(marks: &[bool; N]) -> Vec<Choice> {
        marks.iter().map(|&b| Choice::from(b as u8)).collect()
    }

    /// For every mark pattern of length `N`:
    ///
    /// 1. the output is a permutation of the input — nothing is lost or
    ///    duplicated;
    /// 2. the first `m = count_choices(marks)` entries are exactly the marked
    ///    ones, and the rest exactly the unmarked ones.
    ///
    /// Points are the distinct values `0..N`, so each output entry names the
    /// input position it came from and both claims are decidable.
    fn compaction_is_correct<const N: usize>() {
        let marks: [bool; N] = kani::any();
        let mut points: Vec<u8> = (0..N as u8).collect();

        oblivious_compact_points(&mut points, &choices(&marks));

        let m = marks.iter().filter(|&&b| b).count();
        assert_eq!(points.len(), N, "compaction changed the length");

        let mut seen = [false; N];
        for (i, &p) in points.iter().enumerate() {
            let from = p as usize;
            assert!(from < N, "compaction invented a point");
            assert!(!seen[from], "compaction duplicated a point");
            seen[from] = true;
            assert_eq!(
                marks[from],
                i < m,
                "compaction placed a point on the wrong side of the boundary"
            );
        }
    }

    // Instantiated per length rather than over a symbolic `n`: the recursion
    // splits on whether the length is a power of two, and naming the lengths
    // keeps each proof small enough to discharge quickly.
    //
    // The bound reaches past eight because eight is one short of the
    // interesting case. At `n <= 8` the size-8 block is only ever entered with
    // `offset == 0` (`n == 8` forces `n2 == 0`, so `m == 0`), and a rotation
    // that compounds `offset` across three levels first appears at `n == 9`.
    //
    // Above nine the lengths are sampled rather than swept: solving is seconds
    // but Kani builds a goto program per harness, which dominates the job's
    // wall clock. 12 puts a non-power-of-two split under a size-8 block, and
    // 16 is the next full power of two.
    macro_rules! compaction_proof {
        ($name:ident, $n:literal, $unwind:literal) => {
            #[kani::proof]
            #[kani::unwind($unwind)]
            fn $name() {
                compaction_is_correct::<$n>();
            }
        };
    }

    compaction_proof!(compaction_is_correct_1, 1, 4);
    compaction_proof!(compaction_is_correct_2, 2, 4);
    compaction_proof!(compaction_is_correct_3, 3, 5);
    compaction_proof!(compaction_is_correct_4, 4, 6);
    compaction_proof!(compaction_is_correct_5, 5, 7);
    compaction_proof!(compaction_is_correct_6, 6, 8);
    compaction_proof!(compaction_is_correct_7, 7, 9);
    compaction_proof!(compaction_is_correct_8, 8, 10);
    compaction_proof!(compaction_is_correct_9, 9, 11);
    compaction_proof!(compaction_is_correct_12, 12, 14);
    compaction_proof!(compaction_is_correct_16, 16, 18);

    /// The same contract over the two-field payload the caller actually moves.
    ///
    /// Every proof above runs on bare `u8`, which never touches `Evaluation`'s
    /// hand-written [`ConditionallySelectable`]. Coupling `y` to `x` catches a
    /// transposition in that impl — the coordinates have to travel together.
    #[kani::proof]
    #[kani::unwind(10)]
    fn compaction_moves_evaluations_whole() {
        const N: usize = 8;
        let marks: [bool; N] = kani::any();
        let mut points: Vec<Evaluation<u8>> =
            (0..N as u8).map(|i| Evaluation { x: i, y: !i }).collect();

        oblivious_compact_points(&mut points, &choices(&marks));

        let m = marks.iter().filter(|&&b| b).count();
        let mut seen = [false; N];
        for (i, point) in points.iter().enumerate() {
            let from = point.x as usize;
            assert!(from < N, "compaction invented a point");
            assert!(!seen[from], "compaction duplicated a point");
            seen[from] = true;
            assert_eq!(point.y, !point.x, "compaction split an evaluation");
            assert_eq!(
                marks[from],
                i < m,
                "compaction placed a point on the wrong side of the boundary"
            );
        }
    }

    /// Memory compaction does not depend on the marks.
    fn access_pattern_is_oblivious<const N: usize>() {
        let left: [bool; N] = kani::any();
        let right: [bool; N] = kani::any();

        let mut points: Vec<u8> = (0..N as u8).collect();
        oblivious_compact_points(&mut points, &choices(&left));
        let left_trace = trace::take();

        let mut points: Vec<u8> = (0..N as u8).collect();
        oblivious_compact_points(&mut points, &choices(&right));
        let right_trace = trace::take();

        assert_eq!(left_trace, right_trace, "marks steered a memory access");
    }

    #[kani::proof]
    #[kani::unwind(64)]
    fn access_pattern_is_oblivious_8() {
        access_pattern_is_oblivious::<8>();
    }

    #[kani::proof]
    #[kani::unwind(128)]
    fn access_pattern_is_oblivious_16() {
        access_pattern_is_oblivious::<16>();
    }

    /// A threshold prover simulates exactly `n - t` branches, whatever it
    /// holds, and never runs a branch it cannot satisfy as real while it has a
    /// choice. The first half is what keeps the witness count off the wire.
    fn simulator_flag_count_is_fixed<const N: usize>() {
        let valid: [bool; N] = kani::any();
        let threshold: usize = kani::any();
        kani::assume(threshold <= N);

        let flags = simulator_flags(&choices(&valid), threshold);

        assert_eq!(flags.len(), N, "flag count does not match the branches");
        assert_eq!(
            count_choices(&flags),
            N - threshold,
            "number of simulated branches leaked the witness count"
        );

        // Below the threshold the prover has to run some unsatisfiable branch
        // for real; at or above it, never.
        if valid.iter().filter(|&&b| b).count() >= threshold {
            for (i, flag) in flags.iter().enumerate() {
                assert!(
                    valid[i] || bool::from(*flag),
                    "ran an unsatisfiable branch for real"
                );
            }
        }
    }

    macro_rules! flag_proof {
        ($name:ident, $n:literal, $unwind:literal) => {
            #[kani::proof]
            #[kani::unwind($unwind)]
            fn $name() {
                simulator_flag_count_is_fixed::<$n>();
            }
        };
    }

    flag_proof!(simulator_flag_count_is_fixed_4, 4, 6);
    flag_proof!(simulator_flag_count_is_fixed_8, 8, 10);
    flag_proof!(simulator_flag_count_is_fixed_16, 16, 18);

    /// `count_choices` counts, and in particular does not wrap: it is what
    /// decides whether a threshold prover holds enough witnesses.
    #[kani::proof]
    #[kani::unwind(17)]
    fn count_choices_counts() {
        let marks: [bool; 16] = kani::any();
        assert_eq!(
            count_choices(&choices(&marks)),
            marks.iter().filter(|&&b| b).count()
        );
    }
}
