// AVXTO Wallet Manager
// Copyright (c) 2026, @REKTBuildr
//
// SPDX-License-Identifier: BSD-3-Clause
// See the LICENSE file in the project root for the full license text.

#include "SecureBytes.h"

#include <openssl/crypto.h>

#include <cstdlib>
#include <cstring>
#include <new>
#include <utility>

#if defined(Q_OS_WIN)
#  include <windows.h>
#else
#  include <sys/mman.h>
#  include <unistd.h>
#endif

namespace {

std::size_t pageSize()
{
#if defined(Q_OS_WIN)
    SYSTEM_INFO info{};
    ::GetSystemInfo(&info);
    return static_cast<std::size_t>(info.dwPageSize);
#else
    const long value = ::sysconf(_SC_PAGESIZE);
    return value > 0 ? static_cast<std::size_t>(value) : std::size_t{4096};
#endif
}

std::size_t roundUpToPage(std::size_t size)
{
    const std::size_t page = pageSize();
    return ((size + page - 1) / page) * page;
}

} // namespace

SecureBytes::SecureBytes(std::size_t size)
{
    if (size == 0)
        return;

    m_capacity = roundUpToPage(size);

#if defined(Q_OS_WIN)
    m_data = static_cast<unsigned char *>(::_aligned_malloc(m_capacity, pageSize()));
    if (!m_data)
        throw std::bad_alloc();
    m_locked = ::VirtualLock(m_data, m_capacity) != 0;
#else
    void *raw = nullptr;
    if (::posix_memalign(&raw, pageSize(), m_capacity) != 0 || !raw) {
        m_capacity = 0;
        throw std::bad_alloc();
    }
    m_data = static_cast<unsigned char *>(raw);
    // Best effort: a failed lock means the pages may reach swap, which is a
    // degradation of the guarantee, not a reason to refuse to work.
    m_locked = ::mlock(m_data, m_capacity) == 0;
#endif

    std::memset(m_data, 0, m_capacity);
    m_size = size;
}

SecureBytes::SecureBytes(const void *data, std::size_t size)
    : SecureBytes(size)
{
    if (size > 0 && data)
        std::memcpy(m_data, data, size);
}

SecureBytes::SecureBytes(SecureBytes &&other) noexcept
    : m_data(std::exchange(other.m_data, nullptr))
    , m_size(std::exchange(other.m_size, 0))
    , m_capacity(std::exchange(other.m_capacity, 0))
    , m_locked(std::exchange(other.m_locked, false))
{
}

SecureBytes &SecureBytes::operator=(SecureBytes &&other) noexcept
{
    if (this != &other) {
        reset();
        m_data = std::exchange(other.m_data, nullptr);
        m_size = std::exchange(other.m_size, 0);
        m_capacity = std::exchange(other.m_capacity, 0);
        m_locked = std::exchange(other.m_locked, false);
    }
    return *this;
}

SecureBytes::~SecureBytes()
{
    reset();
}

void SecureBytes::reset() noexcept
{
    if (!m_data) {
        m_size = 0;
        m_capacity = 0;
        return;
    }

    OPENSSL_cleanse(m_data, m_capacity);

#if defined(Q_OS_WIN)
    if (m_locked)
        ::VirtualUnlock(m_data, m_capacity);
    ::_aligned_free(m_data);
#else
    if (m_locked)
        ::munlock(m_data, m_capacity);
    std::free(m_data);
#endif

    m_data = nullptr;
    m_size = 0;
    m_capacity = 0;
    m_locked = false;
}

SecureBytes SecureBytes::clone() const
{
    return SecureBytes(m_data, m_size);
}

SecureBytes SecureBytes::fromLatin1(std::string_view text)
{
    return SecureBytes(text.data(), text.size());
}

SecureBytes SecureBytes::fromUtf8(const QString &text)
{
    QByteArray utf8 = text.toUtf8();
    SecureBytes result(utf8.constData(), static_cast<std::size_t>(utf8.size()));
    wipe(utf8);
    return result;
}

SecureBytes SecureBytes::adopt(QByteArray &data)
{
    SecureBytes result(data.constData(), static_cast<std::size_t>(data.size()));
    wipe(data);
    return result;
}

QString SecureBytes::toQString() const
{
    return QString::fromUtf8(chars(), static_cast<qsizetype>(m_size));
}

bool SecureBytes::constantTimeEquals(const SecureBytes &other) const noexcept
{
    if (m_size != other.m_size)
        return false;
    if (m_size == 0)
        return true;
    return CRYPTO_memcmp(m_data, other.m_data, m_size) == 0;
}

void wipe(void *data, std::size_t size) noexcept
{
    if (data && size > 0)
        OPENSSL_cleanse(data, size);
}

void wipe(QByteArray &buffer) noexcept
{
    if (!buffer.isEmpty()) {
        // data() detaches, guaranteeing we scrub the buffer we actually own
        // rather than a shared copy-on-write block.
        OPENSSL_cleanse(buffer.data(), static_cast<std::size_t>(buffer.size()));
    }
    buffer.clear();
}

void wipe(QString &buffer) noexcept
{
    if (!buffer.isEmpty()) {
        OPENSSL_cleanse(buffer.data(),
                        static_cast<std::size_t>(buffer.size()) * sizeof(QChar));
    }
    buffer.clear();
}

void wipe(std::string &buffer) noexcept
{
    if (!buffer.empty())
        OPENSSL_cleanse(buffer.data(), buffer.size());
    buffer.clear();
}
