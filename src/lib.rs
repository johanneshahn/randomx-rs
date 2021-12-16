// Copyright 2019. The Tari Project
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
// following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following
// disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
// following disclaimer in the documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
// products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
// WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
// USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//! # randomx-rs
//!
//! The `randomx-rs` crate provides bindings to the `RandomX` proof-of-work (PoW) system as well
//! as the functionality to utilize these bindings.
//!

use bigint::uint::U256;
use std::ptr::null_mut;
use std::ptr::NonNull;
use std::sync::{Arc, RwLock};
use std::thread;

mod bindings;

#[macro_use]
extern crate bitflags;
extern crate libc;

use bindings::{
    randomx_alloc_cache, randomx_alloc_dataset, randomx_cache, randomx_calculate_hash,
    randomx_create_vm, randomx_dataset, randomx_dataset_item_count, randomx_destroy_vm,
    randomx_get_dataset_memory, randomx_init_cache, randomx_init_dataset, randomx_release_cache,
    randomx_release_dataset, randomx_vm, randomx_vm_set_cache, randomx_vm_set_dataset,
    RANDOMX_DATASET_ITEM_SIZE, RANDOMX_HASH_SIZE,
};

use crate::bindings::{
    randomx_calculate_hash_first, randomx_calculate_hash_last, randomx_calculate_hash_next,
    randomx_get_flags,
};
use libc::{c_ulong, c_void};
use std::ptr;
use thiserror::Error;

bitflags! {
/// Indicates to the RandomX library which configuration options to use.
    pub struct RandomXFlag: u32 {
    /// All flags not set, works on all platforms, however is the slowest
        const FLAG_DEFAULT      =0b0000_0000;
    /// Allocate memory in large pages
        const FLAG_LARGE_PAGES  =0b0000_0001;
    /// Use hardware accelerated AES
        const FLAG_HARD_AES     =0b0000_0010;
    /// Use the full dataset
        const FLAG_FULL_MEM     =0b0000_0100;
    /// Use JIT compilation support
        const FLAG_JIT          =0b0000_1000;
    /// When combined with FLAG_JIT, the JIT pages are never writable and executable at the
    /// same time
        const FLAG_SECURE       =0b0001_0000;
    /// Optimize Argon2 for CPUs with the SSSE3 instruction set
        const FLAG_ARGON2_SSSE3 =0b0010_0000;
    /// Optimize Argon2 for CPUs with the AVX2 instruction set
        const FLAG_ARGON2_AVX2  =0b0100_0000;
    /// Optimize Argon2 for CPUs without the AVX2 or SSSE3 instruction sets
        const FLAG_ARGON2       =0b0110_0000;
    }
}

impl RandomXFlag {
    /// Returns the recommended flags to be used.
    ///
    /// Does not include:
    /// * FLAG_LARGE_PAGES
    /// * FLAG_FULL_MEM
    /// * FLAG_SECURE
    ///
    /// The above flags need to be set manually, if required.
    pub fn get_recommended_flags() -> RandomXFlag {
        // c code will always return a value
        RandomXFlag {
            bits: unsafe { randomx_get_flags() },
        }
    }
}

impl Default for RandomXFlag {
    /// Default value for RandomXFlag
    fn default() -> RandomXFlag {
        RandomXFlag::FLAG_DEFAULT
    }
}

#[derive(Debug, Clone, Error)]
/// Custom error enum
pub enum RandomXError {
    #[error("Problem creating the RandomX object:{0}")]
    CreationError(String),
    #[error("Problem with configuration flags:{0}")]
    FlagConfigError(String),
    #[error("Problem with parameters supplied:{0}")]
    ParameterError(String),
    #[error("Unknown problem running RandomX:{0}")]
    Other(String),
}

#[derive(Debug)]
/// Cache structure
pub struct RandomXCache {
    cache: *mut randomx_cache,
}

impl Drop for RandomXCache {
    /// De-allocates memory for the `cache` object
    fn drop(&mut self) {
        unsafe {
            randomx_release_cache(self.cache);
        }
    }
}

impl RandomXCache {
    /// Creates a new cache object, allocates memory to the `cache` object and initializes it with
    /// he key value, error on failure.
    ///
    /// `flags` is any combination of the following two flags:
    /// * FLAG_LARGE_PAGES
    /// * FLAG_JIT
    ///
    /// and (optionally) one of the following flags (depending on instruction set supported):
    /// * FLAG_ARGON2_SSSE3
    /// * FLAG_ARGON2_AVX2
    ///
    /// `key` is a sequence of u8 used to initialize SuperScalarHash.
    pub fn new(flags: RandomXFlag, key: &[u8]) -> Result<RandomXCache, RandomXError> {
        if key.is_empty() {
            return Err(RandomXError::ParameterError("key is empty".to_string()));
        };
        let test = unsafe { randomx_alloc_cache(flags.bits) };
        if test.is_null() {
            Err(RandomXError::CreationError(
                "Could not allocate cache".to_string(),
            ))
        } else {
            let result = RandomXCache { cache: test };
            let key_ptr = key.as_ptr() as *mut c_void;
            let key_size = key.len() as usize;
            unsafe {
                //no way to check if this fails, c code does not return anything
                randomx_init_cache(result.cache, key_ptr, key_size);
            }
            Ok(result)
        }
    }
}

#[derive(Debug)]
/// Dataset structure
pub struct RandomXDataset {
    dataset: *mut randomx_dataset,
    dataset_start: c_ulong,
    dataset_count: c_ulong,
}

impl Drop for RandomXDataset {
    /// De-allocates memory for the `dataset` object.
    fn drop(&mut self) {
        unsafe {
            randomx_release_dataset(self.dataset);
        }
    }
}

impl RandomXDataset {
    /// Creates a new dataset object, allocates memory to the `dataset` object and initializes it,
    /// error on failure.
    ///
    /// `flags` is one of the following:
    /// * FLAG_DEFAULT
    /// * FLAG_LARGE_PAGES
    ///
    /// `cache` is a cache object.
    ///
    /// `start` is the item number where initialization should start, recommended to pass in 0.
    pub fn new(
        flags: RandomXFlag,
        cache: &RandomXCache,
        start: c_ulong,
    ) -> Result<RandomXDataset, RandomXError> {
        let count = c_ulong::from(RANDOMX_DATASET_ITEM_SIZE - 1) - start;
        let test = unsafe { randomx_alloc_dataset(flags.bits) };
        if test.is_null() {
            Err(RandomXError::CreationError(
                "Could not allocate dataset".to_string(),
            ))
        } else {
            let result = RandomXDataset {
                dataset: test,
                dataset_start: start,
                dataset_count: count,
            };
            let item_count = match result.count() {
                Ok(v) => v,
                Err(err) => {
                    return Err(RandomXError::CreationError(format!(
                        "Could not get dataset count:{}",
                        err
                    )))
                }
            };
            // Mirror the assert checks inside randomx_init_dataset call
            if !((start < (item_count as c_ulong) && count <= (item_count as c_ulong))
                || (start + (item_count as c_ulong) <= count))
            {
                return Err(RandomXError::CreationError(format!("Dataset `start` or `count` was out of bounds: start:{}, count:{}, actual count:{}", start,count, item_count)));
            }
            unsafe {
                //no way to check if this fails, c code does not return anything
                randomx_init_dataset(
                    result.dataset,
                    cache.cache,
                    start as c_ulong,
                    count as c_ulong,
                );
            }
            Ok(result)
        }
    }

    /// Returns the number of items in the `dataset` or an error on failure.
    pub fn count(&self) -> Result<u64, RandomXError> {
        match unsafe { randomx_dataset_item_count() } {
            0 => Err(RandomXError::Other("Dataset item count was 0".to_string())),
            x => Ok(x as u64),
        }
    }

    /// Returns the values of the internal memory buffer of the `dataset` or an error on failure.
    pub fn get_data(&self) -> Result<Vec<u8>, RandomXError> {
        let memory = unsafe { randomx_get_dataset_memory(self.dataset) };
        if memory.is_null() {
            return Err(RandomXError::Other(
                "Could not get dataset memory".to_string(),
            ));
        }
        let mut result: Vec<u8> = vec![0u8; self.dataset_count as usize];
        unsafe {
            libc::memcpy(
                result.as_mut_ptr() as *mut c_void,
                memory,
                self.dataset_count as usize,
            );
        }
        Ok(result)
    }
}

#[derive(Debug)]
/// VM structure
pub struct RandomXVM {
    flags: RandomXFlag,
    vm: *mut randomx_vm,
}

impl Drop for RandomXVM {
    /// De-allocates memory for the `VM` object.
    fn drop(&mut self) {
        unsafe {
            randomx_destroy_vm(self.vm);
        }
    }
}

impl RandomXVM {
    /// Creates a new `VM` and initializes it, error on failure.
    ///
    /// `flags` is any combination of the following 5 flags:
    /// * FLAG_LARGE_PAGES
    /// * FLAG_HARD_AES
    /// * FLAG_FULL_MEM
    /// * FLAG_JIT
    /// * FLAG_SECURE
    ///
    /// Or
    ///
    /// * FLAG_DEFAULT
    ///
    /// `cache` is a cache object, optional if FLAG_FULL_MEM is set.
    ///
    /// `dataset` is a dataset object, optional if FLAG_FULL_MEM is not set.
    pub fn new(
        flags: RandomXFlag,
        cache: Option<&RandomXCache>,
        dataset: Option<&RandomXDataset>,
    ) -> Result<RandomXVM, RandomXError> {
        let test: *mut randomx_vm;
        let mut is_full_mem = false;
        let flag_full_mem = RandomXFlag::FLAG_FULL_MEM;

        // intersection of flags
        if flags & flag_full_mem == flag_full_mem {
            is_full_mem = true;
        }

        if cache.is_none() && !is_full_mem {
            return Err(RandomXError::FlagConfigError(
                "No cache and FLAG_FULL_MEM not set".to_string(),
            ));
        }

        if dataset.is_none() && is_full_mem {
            return Err(RandomXError::FlagConfigError(
                "No dataset and FLAG_FULL_MEM set".to_string(),
            ));
        }

        match cache {
            Some(stash) => match dataset {
                Some(data) => unsafe {
                    test = randomx_create_vm(flags.bits, stash.cache, data.dataset)
                },
                None => unsafe {
                    test = randomx_create_vm(flags.bits, stash.cache, ptr::null_mut())
                },
            },
            None => match dataset {
                Some(data) => unsafe {
                    test = randomx_create_vm(flags.bits, ptr::null_mut(), data.dataset)
                },
                None => test = ptr::null_mut(),
            },
        }

        if test.is_null() {
            return Err(RandomXError::CreationError(
                "Failed to allocate VM".to_string(),
            ));
        }

        let result = RandomXVM { vm: test, flags };
        Ok(result)
    }

    /// Re-initializes the `VM` with a new cache that was initialised without
    /// RandomXFlag::FLAG_FULL_MEM.
    pub fn reinit_cache(&self, cache: &RandomXCache) -> Result<(), RandomXError> {
        if self.flags & RandomXFlag::FLAG_FULL_MEM == RandomXFlag::FLAG_FULL_MEM {
            return Err(RandomXError::FlagConfigError(
                "Cannot reinit cache with FLAG_FULL_MEM set".to_string(),
            ));
        }
        //no way to check if this fails, c code does not return anything
        unsafe {
            randomx_vm_set_cache(self.vm, cache.cache);
        }
        Ok(())
    }

    /// Re-initializes the `VM` with a new dataset that was initialised with
    /// RandomXFlag::FLAG_FULL_MEM.
    pub fn reinit_dataset(&self, dataset: &RandomXDataset) -> Result<(), RandomXError> {
        if self.flags & RandomXFlag::FLAG_FULL_MEM != RandomXFlag::FLAG_FULL_MEM {
            return Err(RandomXError::FlagConfigError(
                "Cannot reinit dataset without FLAG_FULL_MEM set".to_string(),
            ));
        }
        //no way to check if this fails, c code does not return anything
        unsafe {
            randomx_vm_set_dataset(self.vm, dataset.dataset);
        }
        Ok(())
    }

    /// Calculates a RandomX hash value and returns it, error on failure.
    ///
    /// `input` is a sequence of u8 to be hashed.
    pub fn calculate_hash(&self, input: &[u8]) -> Result<Vec<u8>, RandomXError> {
        if input.is_empty() {
            return Err(RandomXError::ParameterError("input was empty".to_string()));
        };
        let size_input = input.len() as usize;
        let input_ptr = input.as_ptr() as *mut c_void;
        let arr = [0; RANDOMX_HASH_SIZE as usize];
        let output_ptr = arr.as_ptr() as *mut c_void;
        unsafe {
            randomx_calculate_hash(self.vm, input_ptr, size_input, output_ptr);
        }
        // if this failed, arr should still be empty
        if arr == [0; RANDOMX_HASH_SIZE as usize] {
            return Err(RandomXError::Other(
                "RandomX calculated hash was empty".to_string(),
            ));
        }
        let result = arr.to_vec();
        Ok(result)
    }

    /// Calculates hashes from a set of inputs.
    ///
    /// `input` is an array of a sequence of u8 to be hashed.
    #[allow(clippy::needless_range_loop)] // Range loop is not only for indexing `input`
    pub fn calculate_hash_set(&self, input: &[&[u8]]) -> Result<Vec<Vec<u8>>, RandomXError> {
        if input.is_empty() {
            // Empty set
            return Err(RandomXError::ParameterError("input was empty".to_string()));
        }

        let mut result = Vec::new();
        // For single input
        if input.len() == 1 {
            let hash_result = self.calculate_hash(input[0]);
            return match hash_result {
                Ok(hash) => {
                    result.push(hash);
                    Ok(result)
                }
                Err(e) => Err(e),
            };
        }

        // For multiple inputs
        let mut output_ptr: *mut c_void = ptr::null_mut();
        let arr = [0; RANDOMX_HASH_SIZE as usize];

        // Not len() as last iteration assigns final hash
        let iterations = input.len() + 1;
        for i in 0..iterations {
            if i != iterations - 1 {
                if input[i].is_empty() {
                    // Stop calculations
                    if arr != [0; RANDOMX_HASH_SIZE as usize] {
                        // Complete what was started
                        unsafe {
                            randomx_calculate_hash_last(self.vm, output_ptr);
                        }
                    }
                    return Err(RandomXError::ParameterError("input was empty".to_string()));
                };
                let size_input = input[i].len() as usize;
                let input_ptr = input[i].as_ptr() as *mut c_void;
                output_ptr = arr.as_ptr() as *mut c_void;
                if i == 0 {
                    // For first iteration
                    unsafe {
                        randomx_calculate_hash_first(self.vm, input_ptr, size_input);
                    }
                } else {
                    unsafe {
                        // For every other iteration
                        randomx_calculate_hash_next(self.vm, input_ptr, size_input, output_ptr);
                    }
                }
            } else {
                // For last iteration
                unsafe {
                    randomx_calculate_hash_last(self.vm, output_ptr);
                }
            }

            if i != 0 {
                // First hash is only available in 2nd iteration
                if arr == [0; RANDOMX_HASH_SIZE as usize] {
                    return Err(RandomXError::Other("RandomX hash was zero".to_string()));
                }
                let output: Vec<u8> = arr.to_vec();
                result.push(output);
            }
        }
        Ok(result)
    }
}

struct Wrapper<T>(NonNull<T>);
unsafe impl<T> std::marker::Send for Wrapper<T> {}

pub enum RxAction {
    Changed,
    NotChanged,
}

#[derive(Debug)]
pub struct Trash {
    cache: Option<RxCache>,
    dataset: Option<RxDataset>,
}

impl Trash {
    pub fn empty(&mut self) {
        self.cache = None;
        self.dataset = None;
    }
}

impl Default for Trash {
    fn default() -> Self {
        Trash {
            cache: None,
            dataset: None,
        }
    }
}

#[derive(Debug)]
pub struct RxCache {
    cache: *mut randomx_cache,
}

impl Drop for RxCache {
    fn drop(&mut self) {
        unsafe {
            randomx_release_cache(self.cache);
        }
    }
}

#[derive(Debug)]
pub struct RxDataset {
    dataset: *mut randomx_dataset,
}

impl Drop for RxDataset {
    fn drop(&mut self) {
        unsafe {
            randomx_release_dataset(self.dataset);
        }
    }
}

#[derive(Debug)]
pub struct RxState {
    pub seed: [u8; 32],
    pub hard_aes: bool,
    pub full_mem: bool,
    pub large_pages: bool,
    pub jit_compiler: bool,
    cache: Option<RxCache>,
    dataset: Option<RxDataset>,
    vms: Vec<Arc<RwLock<RxVM>>>,
    trash: Trash,
}

#[derive(Debug, PartialEq)]
pub struct RxVM {
    pub vm: *mut randomx_vm,
}

impl Drop for RxVM {
    fn drop(&mut self) {
        unsafe {
            randomx_destroy_vm(self.vm);
        }
    }
}

unsafe impl Sync for RxState {}
unsafe impl Send for RxState {}

impl RxState {
    pub fn new() -> Self {
        RxState {
            seed: [0; 32],
            hard_aes: false,
            full_mem: false,
            large_pages: false,
            jit_compiler: false,
            cache: None,
            dataset: None,
            vms: vec![],
            trash: Trash::default(),
        }
    }

    pub fn is_initialized(&self) -> bool {
        self.cache.is_some()
    }

    pub fn get_flags(&self) -> RandomXFlag {
        let mut flags = RandomXFlag::get_recommended_flags();

        if self.jit_compiler {
            flags |= RandomXFlag::FLAG_JIT;
        }

        if self.hard_aes {
            flags |= RandomXFlag::FLAG_HARD_AES
        }

        if self.full_mem {
            flags |= RandomXFlag::FLAG_FULL_MEM;
        }

        if self.large_pages {
            flags |= RandomXFlag::FLAG_LARGE_PAGES;
        }

        flags
    }

    pub fn init_cache(&mut self, seed: &[u8]) -> Result<RxAction, &str> {
        if self.cache.is_some() && self.is_same_seed(seed) {
            return Ok(RxAction::NotChanged);
        }

        let flags = self.get_flags();
        let mut cache_ptr = unsafe { randomx_alloc_cache(flags.bits) };

        if cache_ptr.is_null() {
            return Err("cache not allocated");
        }

        unsafe {
            randomx_init_cache(cache_ptr, seed.as_ptr() as *const c_void, seed.len());
        }

        self.trash.cache = self.cache.take();
        self.cache = Some(RxCache { cache: cache_ptr });
        self.seed.copy_from_slice(seed);

        Ok(RxAction::Changed)
    }

    pub fn is_same_seed(&self, seed: &[u8]) -> bool {
        &self.seed == seed
    }

    pub fn init_dataset(&mut self, threads_count: u8) -> Result<(), &str> {
        let cache = self.cache.as_ref().ok_or("cache is not initialized")?;

        //let mut dataset_ptr =
        //	unsafe { randomx_alloc_dataset(randomx_flags_RANDOMX_FLAG_LARGE_PAGES) };
        let flags = self.get_flags();
        let dataset_ptr = unsafe { randomx_alloc_dataset(flags.bits) };

        /*if dataset_ptr.is_null() {
            dataset_ptr = unsafe { randomx_alloc_dataset(self.get_flags()) };
        }*/

        if dataset_ptr.is_null() {
            return Err("it's not possible initialize a dataset");
        }

        let mut threads = Vec::new();
        let mut start: u64 = 0;
        let count: u64 = unsafe { randomx_dataset_item_count() } as u64;
        let perth: u64 = count / threads_count as u64;
        let remainder: u64 = count % threads_count as u64;

        for i in 0..threads_count {
            let cache = Wrapper(NonNull::new(cache.cache).unwrap());
            let dataset = Wrapper(NonNull::new(dataset_ptr).unwrap());
            let count = perth
                + if i == (threads_count - 1) {
                    remainder
                } else {
                    0
                };
            threads.push(thread::spawn(move || {
                let d = dataset.0.as_ptr();
                let c = cache.0.as_ptr();
                unsafe {

                    #[cfg(target_arch = "arm")]
                    randomx_init_dataset(d, c, start as u32, count as u32);
                    #[cfg(not(target_arch = "arm"))]
                    randomx_init_dataset(d, c, start.into(), count.into());
                }
            }));
            start += count;
        }

        for th in threads {
            th.join().map_err(|_| "failed to join threads")?;
        }

        self.trash.dataset = self.dataset.take();
        self.dataset = Some(RxDataset {
            dataset: dataset_ptr,
        });

        Ok(())
    }

    pub fn create_vm(&mut self) -> Result<Arc<RwLock<RxVM>>, &str> {
        let cache = self.cache.as_ref().ok_or("cache is not initialized")?;

        let dataset = self
            .dataset
            .as_ref()
            .map(|d| d.dataset)
            .unwrap_or(null_mut());

        let flags = self.get_flags()
            | if !dataset.is_null() {
                RandomXFlag::FLAG_FULL_MEM
            } else {
                RandomXFlag::FLAG_DEFAULT
            };

        let mut vm = unsafe { randomx_create_vm(flags.bits, cache.cache, dataset) };

        if vm.is_null() {
            vm = unsafe { randomx_create_vm(flags.bits, cache.cache, dataset) };
        }

        if !vm.is_null() {
            self.vms.push(Arc::new(RwLock::new(RxVM { vm })));
            Ok(self.vms.last().unwrap().clone())
        } else {
            Err("unable to create RxVM")
        }
    }

    pub fn get_or_create_vm(&mut self) -> Result<Arc<RwLock<RxVM>>, &str> {
        if self.vms.len() == 0 {
            self.create_vm()
        } else {
            Ok(self.vms.last().unwrap().clone())
        }
    }

    pub fn update_vms(&mut self) {
        for vm in &self.vms {
            let mut vm_lock = vm.write().unwrap();
            unsafe {
                self.cache
                    .as_ref()
                    .map(|x| randomx_vm_set_cache(vm_lock.vm, x.cache));
                self.dataset
                    .as_ref()
                    .map(|x| randomx_vm_set_dataset(vm_lock.vm, x.dataset));
            }
        }

        if self.cache.is_some() {
            self.trash.empty();
        }
    }
}
pub fn slow_hash(state: &mut RxState, data: &[u8], seed: &[u8; 32]) -> U256 {
    let vm = {
        //state.jit_compiler = true;
        if let RxAction::Changed = state.init_cache(seed).unwrap() {
            state.update_vms();
        }
        state.get_or_create_vm().expect("vm not initialized")
    };

    let hash_target = unsafe {
        let mut hash: [u8; 32] = [0; 32];

        randomx_calculate_hash(
            vm.read().unwrap().vm,
            data.as_ptr() as *const c_void,
            data.len(),
            hash.as_mut_ptr() as *mut c_void,
        );

        hash.into()
    };

    hash_target
}
#[cfg(test)]
mod tests {
    use crate::{RandomXCache, RandomXDataset, RandomXFlag, RandomXVM};

    #[test]
    fn lib_alloc_cache() {
        let flags = RandomXFlag::default();
        let key = "Key";
        let cache = RandomXCache::new(flags, key.as_bytes());
        if let Err(i) = cache {
            panic!(format!("Failed to allocate cache, {}", i));
        }
        drop(cache);
    }

    #[test]
    fn lib_alloc_dataset() {
        let flags = RandomXFlag::default();
        let key = "Key";
        let cache = RandomXCache::new(flags, key.as_bytes()).unwrap();
        let dataset = RandomXDataset::new(flags, &cache, 0);
        if let Err(i) = dataset {
            panic!(format!("Failed to allocate dataset, {}", i));
        }
        drop(dataset);
        drop(cache);
    }

    #[test]
    fn lib_alloc_vm() {
        let flags = RandomXFlag::default();
        let key = "Key";
        let cache = RandomXCache::new(flags, key.as_bytes()).unwrap();
        let mut vm = RandomXVM::new(flags, Some(&cache), None);
        if let Err(i) = vm {
            panic!(format!("Failed to allocate vm, {}", i));
        }
        drop(vm);
        let dataset = RandomXDataset::new(flags, &cache, 0).unwrap();
        vm = RandomXVM::new(flags, Some(&cache), Some(&dataset));
        if let Err(i) = vm {
            panic!(format!("Failed to allocate vm, {}", i));
        }
        drop(dataset);
        drop(cache);
        drop(vm);
    }

    #[test]
    fn lib_dataset_memory() {
        let flags = RandomXFlag::default();
        let key = "Key";
        let cache = RandomXCache::new(flags, key.as_bytes()).unwrap();
        let dataset = RandomXDataset::new(flags, &cache, 0).unwrap();
        let memory = dataset.get_data().unwrap_or(std::vec::Vec::new());
        if memory.len() == 0 {
            panic!("Failed to get dataset memory");
        }
        let vec = vec![0u8; memory.len() as usize];
        assert_ne!(memory, vec);
        drop(dataset);
        drop(cache);
    }

    #[test]
    fn lib_calculate_hash() {
        let flags = RandomXFlag::get_recommended_flags();
        let flags2 = flags | RandomXFlag::FLAG_FULL_MEM;
        let key = "Key";
        let input = "Input";
        let cache1 = RandomXCache::new(flags, key.as_bytes()).unwrap();
        let vm1 = RandomXVM::new(flags, Some(&cache1), None).unwrap();
        let hash1 = vm1.calculate_hash(input.as_bytes()).expect("no data");
        let vec = vec![0u8; hash1.len() as usize];
        assert_ne!(hash1, vec);
        let reinit_cache = vm1.reinit_cache(&cache1);
        assert_eq!(reinit_cache.is_ok(), true);
        let hash2 = vm1.calculate_hash(input.as_bytes()).expect("no data");
        assert_ne!(hash2, vec);
        assert_eq!(hash1, hash2);

        let cache2 = RandomXCache::new(flags, key.as_bytes()).unwrap();
        let vm2 = RandomXVM::new(flags, Some(&cache2), None).unwrap();
        let hash3 = vm2.calculate_hash(input.as_bytes()).expect("no data");
        assert_eq!(hash2, hash3);

        let cache3 = RandomXCache::new(flags, key.as_bytes()).unwrap();
        let dataset3 = RandomXDataset::new(flags, &cache3, 0).unwrap();
        let vm3 = RandomXVM::new(flags2, None, Some(&dataset3)).unwrap();
        let hash4 = vm3.calculate_hash(input.as_bytes()).expect("no data");
        assert_ne!(hash3, vec);
        let reinit_dataset = vm3.reinit_dataset(&dataset3);
        assert_eq!(reinit_dataset.is_ok(), true);
        let hash5 = vm3.calculate_hash(input.as_bytes()).expect("no data");
        assert_ne!(hash4, vec);
        assert_eq!(hash4, hash5);

        let cache4 = RandomXCache::new(flags, key.as_bytes()).unwrap();
        let dataset4 = RandomXDataset::new(flags, &cache4, 0).unwrap();
        let vm4 = RandomXVM::new(flags2, Some(&cache4), Some(&dataset4)).unwrap();
        let hash6 = vm3.calculate_hash(input.as_bytes()).expect("no data");
        assert_eq!(hash5, hash6);

        drop(dataset3);
        drop(dataset4);
        drop(cache1);
        drop(cache2);
        drop(cache3);
        drop(vm1);
        drop(vm2);
        drop(vm3);
        drop(vm4);
    }

    #[test]
    fn lib_calculate_hash_set() {
        let flags = RandomXFlag::default();
        let key = "Key";
        let mut inputs = Vec::new();
        inputs.push("Input".as_bytes());
        inputs.push("Input 2".as_bytes());
        inputs.push("Inputs 3".as_bytes());
        let cache = RandomXCache::new(flags, key.as_bytes()).unwrap();
        let vm = RandomXVM::new(flags, Some(&cache), None).unwrap();
        let hashes = vm.calculate_hash_set(inputs.as_slice()).expect("no data");
        assert_eq!(inputs.len(), hashes.len());
        let mut prev_hash = Vec::new();
        let mut i = 0;
        for hash in hashes {
            let vec = vec![0u8; hash.len() as usize];
            assert_ne!(hash, vec);
            assert_ne!(hash, prev_hash);
            let compare = vm.calculate_hash(inputs[i]).unwrap(); //sanity check
            assert_eq!(hash, compare);
            prev_hash = hash;
            i += 1;
        }
        drop(cache);
        drop(vm);
    }

    #[test]
    fn lib_calculate_hash_is_consistent() {
        let flags = RandomXFlag::get_recommended_flags();
        let key = "Key";
        let input = "Input";
        let cache = RandomXCache::new(flags, key.as_bytes()).unwrap();
        let dataset = RandomXDataset::new(flags, &cache, 0).unwrap();
        let vm = RandomXVM::new(flags, Some(&cache), Some(&dataset)).unwrap();
        let hash = vm.calculate_hash(input.as_bytes()).expect("no data");
        assert_eq!(
            hash,
            [
                114, 81, 192, 5, 165, 242, 107, 100, 184, 77, 37, 129, 52, 203, 217, 227, 65, 83,
                215, 213, 59, 71, 32, 172, 253, 155, 204, 111, 183, 213, 157, 155
            ]
        );
        drop(vm);
        drop(dataset);
        drop(cache);

        let cache1 = RandomXCache::new(flags, key.as_bytes()).unwrap();
        let dataset1 = RandomXDataset::new(flags, &cache1, 0).unwrap();
        let vm1 = RandomXVM::new(flags, Some(&cache1), Some(&dataset1)).unwrap();
        let hash1 = vm1.calculate_hash(input.as_bytes()).expect("no data");
        assert_eq!(
            hash1,
            [
                114, 81, 192, 5, 165, 242, 107, 100, 184, 77, 37, 129, 52, 203, 217, 227, 65, 83,
                215, 213, 59, 71, 32, 172, 253, 155, 204, 111, 183, 213, 157, 155
            ]
        );
        drop(vm1);
        drop(dataset1);
        drop(cache1);
    }
}
