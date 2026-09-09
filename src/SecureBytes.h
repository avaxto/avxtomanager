// AVXTO Wallet Manager
// Copyright (c) 2026, @REKTBuildr
//
// SPDX-License-Identifier: BSD-3-Clause
// See the LICENSE file in the project root for the full license text.

#pragma once

#include <QByteArray>
#include <QString>

#include <cstddef>
#include <string>
#include <string_view>

/*!
 * \brief Owning byte buffer that is best-effort kept out of swap and always
 *        wiped on destruction.
 *
 * The buffer is allocated page-aligned so it can be handed to mlock(); if the
 * lock fails (RLIMIT_MEMLOCK, unsupported platform) we carry on unlocked
 * rather than failing the operation, but the wipe on destruction is
 * unconditional and uses OPENSSL_cleanse so the compiler cannot elide it.
 *
 * Move-only: copying a secret by accident is exactly the mistake this type
 * exists to prevent.
 */
class SecureBytes
{
public:
    SecureBytes() noexcept = default;
    explicit SecureBytes(std::size_t size);
    SecureBytes(const void *data, std::size_t size);

    SecureBytes(SecureBytes &&other) noexcept;
    SecureBytes &operator=(SecureBytes &&other) noexcept;

    SecureBytes(const SecureBytes &) = delete;
    SecureBytes &operator=(const SecureBytes &) = delete;

    ~SecureBytes();

    //! Explicit deep copy. Spelled out so it never happens implicitly.
    [[nodiscard]] SecureBytes clone() const;

    [[nodiscard]] static SecureBytes fromLatin1(std::string_view text);
    [[nodiscard]] static SecureBytes fromUtf8(const QString &text);

    //! Adopts \a data and wipes the source buffer in place.
    [[nodiscard]] static SecureBytes adopt(QByteArray &data);

    [[nodiscard]] unsigned char *data() noexcept { return m_data; }
    [[nodiscard]] const unsigned char *data() const noexcept { return m_data; }
    [[nodiscard]] char *chars() noexcept { return reinterpret_cast<char *>(m_data); }
    [[nodiscard]] const char *chars() const noexcept { return reinterpret_cast<const char *>(m_data); }

    [[nodiscard]] std::size_t size() const noexcept { return m_size; }
    [[nodiscard]] bool isEmpty() const noexcept { return m_size == 0; }

    [[nodiscard]] std::string_view view() const noexcept { return {chars(), m_size}; }

    /*!
     * Materialises the contents as a QString. This necessarily creates a copy
     * outside the protected allocation, so callers must treat the result as
     * short-lived and pass it to wipe() when done.
     */
    [[nodiscard]] QString toQString() const;

    //! Constant-time equality. Length inequality short-circuits (lengths are not secret).
    [[nodiscard]] bool constantTimeEquals(const SecureBytes &other) const noexcept;

    void reset() noexcept;

private:
    unsigned char *m_data = nullptr;  //!< page-aligned, mlock'd where permitted
    std::size_t m_size = 0;           //!< bytes requested by the caller
    std::size_t m_capacity = 0;       //!< bytes actually allocated (page multiple)
    bool m_locked = false;
};

//! Overwrites the payload of a transient Qt/std buffer before it is released.
void wipe(QByteArray &buffer) noexcept;
void wipe(QString &buffer) noexcept;
void wipe(std::string &buffer) noexcept;
void wipe(void *data, std::size_t size) noexcept;
